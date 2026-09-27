(in-package #:autolith)

;;;; -- Trusted MCP Service --

(defclass broker-mcp-service ()
  ((configuration
    :initarg :configuration
    :reader broker-mcp-service-configuration
    :type configuration
    :documentation "The launcher's private MCP configuration.")
   (manager
    :initform nil
    :accessor broker-mcp-service-manager
    :documentation "The lazily connected trusted MCP runtime.")
   (registry
    :initform nil
    :accessor broker-mcp-service-registry
    :documentation "The exact broker-owned helper and provider tool registry.")
   (lock
    :initform (make-lock "Broker MCP discovery")
    :reader broker-mcp-service-lock
    :documentation "Serializes initial connection and registry refresh."))
  (:documentation "Launcher-owned MCP registrations and credentialed clients."))

(-> broker-mcp-service-create (configuration) broker-mcp-service)
(defun broker-mcp-service-create (configuration)
  "Load only the launcher's private global MCP definitions into a lazy service."
  (let* ((path (configuration-mcp-path configuration))
         (status (platform-path-status *platform* path)))
    (when status
      (unless (and (eq (platform-file-status-kind status) ':file)
                   (platform-file-status-owned-p status)
                   (platform-file-status-private-p status))
        (error 'broker-server-error
               :message "The broker MCP configuration file is not private."
               :reason ':configuration))
      (dolist (definition (mcp-configuration-read configuration))
        (register-mcp-server definition :source ':config)))
    (make-instance 'broker-mcp-service :configuration configuration)))

(-> broker-mcp-service-close (broker-mcp-service) null)
(defun broker-mcp-service-close (service)
  "Close every trusted MCP client owned by SERVICE."
  (when (broker-mcp-service-manager service)
    (mcp-manager-close (broker-mcp-service-manager service)))
  nil)

(-> broker-mcp--ensure-registry (broker-mcp-service) (option tool-registry))
(defun broker-mcp--ensure-registry (service)
  "Connect trusted registrations once and retain their exact discovered tools."
  (with-lock-held ((broker-mcp-service-lock service))
    (unless (broker-mcp-service-registry service)
      (when (mcp-server-registrations)
        (let* ((manager (mcp-manager-create
                         (broker-mcp-service-configuration service)))
               (registry (make-instance 'tool-registry)))
          (handler-case
              (progn
                (mcp-tool-registry-register-manager registry manager)
                (setf (broker-mcp-service-manager service) manager
                      (broker-mcp-service-registry service) registry))
            (error (condition)
              (mcp-manager-close manager)
              (error condition))))))
    (broker-mcp-service-registry service)))

(-> broker-mcp--tool-record (tool) list)
(defun broker-mcp--tool-record (tool)
  "Project one discovered tool into bounded, portable agent-visible metadata."
  (append
   (list ':namespace (tool-namespace tool)
         ':name (tool-name tool)
         ':description (tool-description tool)
         ':parameters (json-encode (tool-parameters tool)))
   (when (typep tool 'mcp-provider-tool)
     (list ':server
           (mcp-server-runtime-name (mcp-provider-tool-runtime tool))
           ':raw-tool
           (mcp-tool-name (mcp-provider-tool-raw-tool tool))
           ':read-only-p (mcp-provider-tool-read-only-p tool)
           ':child-safe-p (mcp-provider-tool-configured-child-safe-p tool)))))

(-> broker-mcp--tool-records (broker-mcp-service) list)
(defun broker-mcp--tool-records (service)
  "Return detached metadata for every currently trusted MCP tool."
  (let ((registry (broker-mcp--ensure-registry service)))
    (when registry
      (mapcar #'broker-mcp--tool-record (tool-registry-tools registry)))))

(-> broker-mcp-discover (broker-mcp-service string function) null)
(defun broker-mcp-discover (service source write-frame)
  "Advertise broker-owned MCP schemas without revealing transport credentials."
  (unless (string= source "")
    (error 'broker-protocol-error
           :message "MCP discovery takes no agent payload."
           :reason ':payload))
  (funcall write-frame
           (list ':broker-result ':status ':mcp-tools
                 ':tools (broker-mcp--tool-records service)))
  nil)

(-> broker-mcp--payload (string) json-object)
(defun broker-mcp--payload (source)
  "Require an exact MCP tool identity and one JSON argument object."
  (let ((value (handler-case (json-decode source)
                 (error () nil))))
    (unless (and (json-object-p value)
                 (= (hash-table-count value) 3)
                 (every (lambda (name) (nth-value 1 (gethash name value)))
                        '("namespace" "name" "arguments"))
                 (non-empty-string-p (json-get value "namespace"))
                 (<= (length (json-get value "namespace")) 128)
                 (non-empty-string-p (json-get value "name"))
                 (<= (length (json-get value "name")) 256)
                 (json-object-p (json-get value "arguments")))
      (error 'broker-protocol-error
             :message "The MCP broker payload is invalid."
             :reason ':payload))
    value))

(-> broker-mcp--tool (broker-mcp-service json-object) tool)
(defun broker-mcp--tool (service payload)
  "Resolve an agent request only to a tool advertised by trusted discovery."
  (let* ((registry (broker-mcp--ensure-registry service))
         (tool (and registry
                    (tool-registry-find
                     registry
                     (json-get payload "namespace")
                     (json-get payload "name")))))
    (unless (and tool
                 (or (typep tool 'mcp-provider-tool)
                     (typep tool 'mcp-resource-tool)))
      (error 'broker-protocol-error
             :message "The MCP tool is not registered in the broker."
             :reason ':target))
    tool))

(-> broker-mcp--approve (tool json-object) boolean)
(defun broker-mcp--approve (tool arguments)
  "Apply only trusted MCP policy to the complete agent-supplied arguments."
  (let ((policy (if (typep tool 'mcp-provider-tool)
                    (mcp-provider-tool-approval-policy tool)
                    ':prompt)))
    (cond
      ((eq policy ':deny)
       nil)
      ((eq policy ':allow)
       t)
      ((and (eq policy ':read-only)
            (typep tool 'mcp-provider-tool)
            (mcp-provider-tool-read-only-p tool))
       t)
      (t
       (broker-terminal-approve
        (format nil "MCP action: ~A~%Arguments: ~A"
                (tool-canonical-name tool)
                (json-encode arguments)))))))

(-> broker-mcp--provider-call (mcp-provider-tool json-object) json-object)
(defun broker-mcp--provider-call (tool arguments)
  "Run one exact server-advertised tool and redact its result before IPC."
  (let ((runtime (mcp-provider-tool-runtime tool)))
    (mcparen:mcp-server-runtime-call
     runtime
     (lambda (client)
       (let ((result
               (mcp-client-call-tool
                client (mcp-provider-tool-raw-tool tool) arguments
                :timeout
                (mcp-server-configuration-tool-timeout-seconds
                 (mcp-server-runtime-configuration runtime)))))
         (json-object
          "kind" "tool"
          "server" (mcp-server-runtime-name runtime)
          "tool" (mcp-tool-name (mcp-provider-tool-raw-tool tool))
          "result" (mcp-tools--sanitize-value (mcp-call-result-raw result))))))))

(-> broker-mcp--helper-call (broker-mcp-service mcp-resource-tool json-object)
    json-object)
(defun broker-mcp--helper-call (service tool arguments)
  "Run one registered MCP helper with broker-owned clients and policy."
  (let ((manager (broker-mcp-service-manager service))
        (server (tool-argument arguments "server")))
    (typecase tool
      (mcp-status-tool
       (json-object "kind" "text" "success" t
                    "content" (mcp-manager-render-status manager)))
      (mcp-refresh-tool
       (mcp-tool-registry-refresh (broker-mcp-service-registry service))
       (json-object "kind" "refresh"
                    "status" (mcp-manager-render-status manager)))
      ((or mcp-resources-tool mcp-resource-templates-tool mcp-prompts-tool)
       (let* ((list-function
                (typecase tool
                  (mcp-resources-tool #'mcp-client-list-resources)
                  (mcp-resource-templates-tool
                   #'mcp-client-list-resource-templates)
                  (mcp-prompts-tool #'mcp-client-list-prompts)))
              (result
                (mcp-tools--server-list-result
                 manager
                 :server-name server
                 :list-function
                 (lambda (client)
                   (mcp-tools--sanitize-value
                    (funcall list-function client)))
                 :item-label
                 (typecase tool
                   (mcp-resources-tool "resources")
                   (mcp-resource-templates-tool "resource templates")
                   (mcp-prompts-tool "prompts")))))
         (json-object "kind" "text"
                      "success" (tool-result-success-p result)
                      "content" (tool-result-content result))))
      (mcp-read-resource-tool
       (let* ((uri (tool-argument arguments "uri" :required t))
              (runtime (mcp-manager--runtime-required manager server)))
         (unless (non-empty-string-p uri)
           (error 'broker-protocol-error
                  :message "An MCP resource URI is required."
                  :reason ':payload))
         (mcparen:mcp-server-runtime-call
          runtime
          (lambda (client)
            (json-object
             "kind" "resource"
             "server" server
             "result"
             (mcp-tools--sanitize-value
              (mcp-client-read-resource client uri)))))))
      (mcp-get-prompt-tool
       (let* ((name (tool-argument arguments "name" :required t))
              (prompt-arguments (tool-argument arguments "arguments"))
              (runtime (mcp-manager--runtime-required manager server)))
         (unless (and (non-empty-string-p name)
                      (or (null prompt-arguments)
                          (and (json-object-p prompt-arguments)
                               (loop for value being the hash-values of prompt-arguments
                                     always (stringp value)))))
           (error 'broker-protocol-error
                  :message "The MCP prompt arguments are invalid."
                  :reason ':payload))
         (mcparen:mcp-server-runtime-call
          runtime
          (lambda (client)
            (json-object
             "kind" "prompt"
             "server" server
             "name" name
             "result"
             (mcp-tools--sanitize-value
              (mcp-client-get-prompt client name prompt-arguments)))))))
      (otherwise
       (error 'broker-protocol-error
              :message "The MCP helper is unavailable."
              :reason ':target)))))

(-> broker-mcp-call (broker-mcp-service string function) null)
(defun broker-mcp-call (service source write-frame)
  "Authorize and execute one exact MCP action through trusted clients."
  (let* ((payload (broker-mcp--payload source))
         (tool (broker-mcp--tool service payload))
         (arguments (json-get payload "arguments")))
    (unless (or (typep tool 'mcp-status-tool)
                (broker-mcp--approve tool arguments))
      (funcall write-frame '(:broker-result :status :denied))
      (return-from broker-mcp-call nil))
    (let ((result (if (typep tool 'mcp-provider-tool)
                      (broker-mcp--provider-call tool arguments)
                      (broker-mcp--helper-call service tool arguments))))
      (funcall write-frame
               '(:broker-result :status :open :code 200))
      (with-input-from-string (stream (json-encode result))
        (broker-provider--copy-stream stream write-frame))))
  nil)
