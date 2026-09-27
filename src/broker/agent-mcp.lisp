(in-package #:autolith)

;;;; -- Agent MCP Broker Route --

(defclass broker-mcp-tool (tool)
  ((server
    :initarg :server
    :reader broker-mcp-tool-server
    :type (option string)
    :documentation "The broker-advertised server name for a provider tool.")
   (raw-tool
    :initarg :raw-tool
    :reader broker-mcp-tool-raw-tool
    :type (option string)
    :documentation "The exact name advertised by the MCP server.")
   (read-only-p
    :initarg :read-only-p
    :reader broker-mcp-tool-read-only-p
    :type boolean
    :documentation "The broker's trusted read-only classification.")
   (child-safe-p
    :initarg :child-safe-p
    :reader broker-mcp-tool-child-safe-p
    :type boolean
    :documentation "The broker's explicit child-task grant."))
  (:documentation "An agent-visible MCP tool whose sole executor is the broker."))

(defmethod tool-storm-guard-exempt-p ((tool broker-mcp-tool))
  "Exempt only broker-classified read-only calls from the storm guard."
  (broker-mcp-tool-read-only-p tool))

(defmethod tool-compact-result-visible-p ((tool broker-mcp-tool))
  "Keep brokered mutation outcomes visible in compact presentation."
  (not (broker-mcp-tool-read-only-p tool)))

(defmethod tool-child-safe-p ((tool broker-mcp-tool))
  "Honor the broker's exact child-task grant."
  (broker-mcp-tool-child-safe-p tool))

(defmethod tool-authorization-identity-fields ((tool broker-mcp-tool))
  "Identify a brokered provider call by its exact MCP source."
  (when (broker-mcp-tool-server tool)
    (list (list "MCP server" (broker-mcp-tool-server tool))
          (list "MCP tool" (broker-mcp-tool-raw-tool tool)))))

(defmethod tool-decode-arguments ((tool broker-mcp-tool) source)
  "Keep MCP false, null, and array values distinct across the broker hop."
  (handler-case
      (let ((arguments (json-decode source)))
        (unless (json-object-p arguments)
          (error "MCP arguments must be one JSON object."))
        arguments)
    (error ()
      (error 'tool-error
             :message "MCP tool arguments must be one JSON object."
             :tool-name (tool-canonical-name tool)))))

(-> broker-mcp-agent--discover () list)
(defun broker-mcp-agent--discover ()
  "Receive only bounded tool descriptions from the trusted broker."
  (broker-client-request
   ':mcp-discover "mcp" ""
   (lambda (stream)
     (let ((frame (management-repl-read-frame
                   stream *broker-maximum-frame-size*)))
       (unless (and (listp frame)
                    (eql (ignore-errors (list-length frame)) 5)
                    (equal (subseq frame 0 4)
                           '(:broker-result :status :mcp-tools :tools))
                    (listp (fifth frame))
                    (<= (length (fifth frame)) 1024))
         (error 'broker-protocol-error
                :message "The broker returned invalid MCP discovery."
                :reason ':response))
       (fifth frame)))))

(-> broker-mcp-agent--tool (list) broker-mcp-tool)
(defun broker-mcp-agent--tool (record)
  "Validate one detached broker tool record before exposing its schema."
  (let ((namespace (getf record ':namespace))
        (name (getf record ':name))
        (description (getf record ':description))
        (source (getf record ':parameters))
        (server (getf record ':server))
        (raw-tool (getf record ':raw-tool)))
    (unless (and (listp record)
                 (eql (ignore-errors (list-length record))
                      (if server 16 8))
                 (non-empty-string-p namespace)
                 (<= (length namespace) 128)
                 (non-empty-string-p name)
                 (<= (length name) 256)
                 (non-empty-string-p description)
                 (<= (length description) 8192)
                 (stringp source)
                 (<= (length source) *broker-maximum-frame-size*)
                 (or (null server)
                     (and (non-empty-string-p server)
                          (non-empty-string-p raw-tool)))
                 (member (getf record ':read-only-p) '(nil t))
                 (member (getf record ':child-safe-p) '(nil t)))
      (error 'broker-protocol-error
             :message "The broker returned invalid MCP tool metadata."
             :reason ':response))
    (let ((parameters (handler-case (json-decode source)
                        (error () nil))))
      (unless (json-object-p parameters)
        (error 'broker-protocol-error
               :message "The broker returned an invalid MCP tool schema."
               :reason ':response))
      (make-instance 'broker-mcp-tool
                     :namespace namespace :name name
                     :description description :parameters parameters
                     :server server :raw-tool raw-tool
                     :read-only-p (and (getf record ':read-only-p) t)
                     :child-safe-p (and (getf record ':child-safe-p) t)))))

(-> broker-mcp-agent-register (tool-registry) tool-registry)
(defun broker-mcp-agent-register (registry)
  "Replace agent MCP tools only after complete broker discovery validates."
  (let ((tools (mapcar #'broker-mcp-agent--tool
                       (broker-mcp-agent--discover)))
        (names (make-hash-table :test #'equal)))
    (dolist (tool (tool-registry-tools registry))
      (unless (and (typep tool 'broker-mcp-tool)
                   (not (typep tool 'broker-registered-agent-tool)))
        (setf (gethash (tool-canonical-name tool) names) t)))
    (dolist (tool tools)
      (when (gethash (tool-canonical-name tool) names)
        (error 'broker-protocol-error
               :message "Broker MCP discovery contains a conflicting tool."
               :reason ':response))
      (setf (gethash (tool-canonical-name tool) names) t))
    (tool-registry-delete-if registry
                             (lambda (tool)
                               (and (typep tool 'broker-mcp-tool)
                                    (not (typep tool
                                                'broker-registered-agent-tool)))))
    (dolist (tool tools)
      (tool-registry-register registry tool)))
  registry)

(-> broker-mcp-agent--call (broker-mcp-tool json-object)
    (values (option json-object) boolean))
(-> broker-mcp-agent--read-body (stream) string)
(defun broker-mcp-agent--read-body (stream)
  "Read one broker body with a fixed aggregate limit."
  (with-output-to-string (output)
    (loop for character = (read-char stream nil nil)
          for count from 0
          while character
          do (when (>= count (* 64 1024 1024))
               (error 'broker-protocol-error
                      :message "The broker MCP result is too large."
                      :reason ':response))
             (write-char character output))))

(defun broker-mcp-agent--call (tool arguments)
  "Call one exact broker tool, returning its body or a trusted denial."
  (broker-client-request
   ':mcp-call "mcp"
   (json-encode
    (json-object "namespace" (tool-namespace tool)
                 "name" (tool-name tool)
                 "arguments" arguments))
   (lambda (stream)
     (let ((frame (management-repl-read-frame
                   stream *broker-maximum-frame-size*)))
       (when (equal frame '(:broker-result :status :denied))
         (return-from broker-mcp-agent--call (values nil nil)))
       (unless (equal frame '(:broker-result :status :open :code 200))
         (error 'broker-protocol-error
                :message "The broker returned an invalid MCP call response."
                :reason ':response))
       (let* ((body (broker-mcp-agent--read-body
                     (make-instance 'broker-response-stream :source stream)))
              (result (handler-case (json-decode body)
                        (error () nil))))
         (unless (json-object-p result)
           (error 'broker-protocol-error
                  :message "The broker returned invalid MCP call data."
                  :reason ':response))
         (values result t))))))

(-> broker-mcp-agent--result (broker-mcp-tool tool-context json-object)
    tool-result)
(defun broker-mcp-agent--result (tool context body)
  "Render a broker response with the ordinary MCP content projections."
  (let ((kind (json-get body "kind"))
        (server (broker-mcp-tool-server tool)))
    (cond
      ((string= kind "tool")
       (let* ((result (json-get body "result"))
              (content (mcp-tools--json-sequence
                        (json-get result "content")))
              (error-p (json-get result "isError")))
         (multiple-value-bind (text attachments blocks)
             (mcp-tools--render-content
              context content
              (format nil "mcp://~A/~A" server
                      (broker-mcp-tool-raw-tool tool))
              :structured-content (json-get result "structuredContent")
              :include-images-p (not error-p))
           (if error-p
               (tool-failure text)
               (tool-success
                (if (non-empty-string-p text) text
                    "The MCP server returned an empty result.")
                :content-blocks (when attachments blocks))))))
      ((string= kind "resource")
       (multiple-value-bind (text attachments blocks)
           (mcp-tools--render-content
            context
            (mapcar (lambda (resource)
                      (json-object "type" "resource"
                                   "resource" resource))
                    (mcp-tools--json-sequence
                     (json-get (json-get body "result") "contents")))
            (format nil "mcp://~A/resource" (json-get body "server")))
         (tool-success
          (if (non-empty-string-p text) text
              "The MCP resource contained no content.")
          :content-blocks (when attachments blocks))))
      ((string= kind "prompt")
       (mcp-tools--prompt-result
        context (json-get body "result")
        (format nil "mcp://~A/prompt/~A"
                (json-get body "server") (json-get body "name"))))
      ((string= kind "refresh")
       (broker-mcp-agent-register (tool-context-registry context))
       (tool-success (json-get body "status")))
      ((string= kind "text")
       (if (json-get body "success")
           (tool-success (json-get body "content"))
           (tool-failure (json-get body "content"))))
      (t
       (error 'broker-protocol-error
              :message "The broker returned an unknown MCP result kind."
              :reason ':response)))))

(defmethod tool-execute
    ((tool broker-mcp-tool) (context tool-context) (arguments hash-table))
  "Execute through the broker's exact target and trusted approval policy."
  (multiple-value-bind (body allowed-p)
      (broker-mcp-agent--call tool arguments)
    (if allowed-p
        (broker-mcp-agent--result tool context body)
        (tool-failure "The trusted launcher denied this MCP action."))))
