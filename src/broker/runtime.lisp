(in-package #:autolith)

;;;; -- Trusted Broker Image Entry --

(defparameter *broker-image-argument* "--autolith-internal-broker"
  "The stable launcher's private entry into the preloaded broker image.")

(defparameter *broker-auth-image-argument* "--autolith-internal-auth"
  "The stable launcher's trusted terminal authentication entry.")

(-> broker--configuration () configuration)
(defun broker--configuration ()
  "Create broker-owned configuration under launcher-only roots."
  (configuration-create
   :config-root (platform-launcher-root *platform* ':config)
   :data-root (platform-launcher-root *platform* ':data)
   :state-root (platform-launcher-root *platform* ':state)
   :cache-root (platform-launcher-root *platform* ':cache)
   :defer-provider-validation-p t
   :durable-p nil))

(-> broker--load-trusted-init (configuration) null)
(defun broker--load-trusted-init (configuration)
  "Load only the launcher-owned global initialization file."
  (let* ((root (config :config-root configuration))
         (root-status (platform-path-status *platform* root))
         (pathname (configuration-user-init-path configuration))
         (status (platform-path-status *platform* pathname)))
    (unless (and root-status
                 (eq (platform-file-status-kind root-status) ':directory)
                 (platform-file-status-owned-p root-status)
                 (platform-file-status-private-p root-status))
      (error 'broker-server-error
             :message "The broker configuration root is not private."
             :reason ':configuration))
    (when status
      (unless (and (eq (platform-file-status-kind status) ':file)
                   (platform-file-status-owned-p status)
                   (platform-file-status-private-p status))
        (error 'broker-server-error
               :message "The broker initialization file is not private."
               :reason ':configuration))
      (let ((*package* (find-package '#:autolith))
            (*configuration* configuration))
        (load pathname :verbose nil :print nil))))
  nil)

(-> broker--handle-request
    (configuration list function &key (:mcp-service broker-mcp-service))
    null)
(defun broker--handle-request (configuration request write-frame &key mcp-service)
  "Dispatch one validated request using only trusted broker configuration."
  (let ((operation (getf (rest request) ':operation))
        (target (getf (rest request) ':target))
        (payload (getf (rest request) ':payload)))
    (case operation
      (:provider-turn
       (broker-provider-stream configuration target payload write-frame))
      (:provider-compaction
       (broker-provider-compact configuration target payload write-frame))
      (:provider-models
       (broker-provider-discover configuration target payload write-frame))
      (:mcp-discover
       (unless (string= target "mcp")
         (error 'broker-protocol-error
                :message "MCP discovery has an invalid target."
                :reason ':target))
       (broker-mcp-discover mcp-service payload write-frame))
      (:mcp-call
       (unless (string= target "mcp")
         (error 'broker-protocol-error
                :message "MCP calls have an invalid target."
                :reason ':target))
       (broker-mcp-call mcp-service payload write-frame))
      (:registered-tool-discover
       (unless (string= target "registered")
         (error 'broker-protocol-error
                :message "Trusted tool discovery has an invalid target."
                :reason ':target))
       (broker-registered-tools-discover payload write-frame))
      (:registered-tool-call
       (unless (string= target "registered")
         (error 'broker-protocol-error
                :message "A trusted tool call has an invalid target."
                :reason ':target))
       (broker-registered-tools-call payload write-frame))
      (otherwise
       (error 'broker-protocol-error
              :message "The requested broker operation is unavailable."
              :reason ':operation))))
  nil)

(-> broker-run (pathname) null)
(defun broker-run (socket-pathname)
  "Serve trusted broker requests from the launcher's private socket."
  (unless (platform-supports-p *platform* ':local-sockets)
    (error 'broker-server-error
           :message "This host cannot run the credential broker."
           :reason ':unsupported))
  (let* ((configuration (broker--configuration))
         (socket-directory
           (uiop:pathname-directory-pathname socket-pathname))
         (component
           (first (last (pathname-directory socket-directory)))))
    (unless (and (uiop:subpathp socket-pathname #P"/tmp/")
                 (string= (file-namestring socket-pathname) "broker.sock")
                 (stringp component)
                 (<= (length "autolith-broker.") (length component))
                 (string= component "autolith-broker."
                          :end1 (length "autolith-broker.")))
      (error 'broker-server-error
             :message "The broker socket is outside its private runtime directory."
             :reason ':path))
    (configuration-ensure-directories configuration)
    (mcp--registry-restore nil)
    (setf *broker-registered-tools* nil)
    (let ((*broker-registration-open-p* t))
      (broker--load-trusted-init configuration))
    (provider-bootstrap-configuration configuration)
    (let* ((*configuration* configuration)
           (mcp-service (broker-mcp-service-create configuration))
           (server
             (broker-server-create
              socket-pathname
              (lambda (request write-frame)
                (broker--handle-request
                 configuration request write-frame
                 :mcp-service mcp-service)))))
      (unwind-protect
           (broker-server-serve server)
        (broker-mcp-service-close mcp-service))))
  nil)

(-> broker-authenticate ((option string) (option string)) null)
(defun broker-authenticate (selection method)
  "Authenticate one registered provider in the trusted launcher image."
  (let ((configuration (broker--configuration)))
    (configuration-ensure-directories configuration)
    (let ((*broker-registration-open-p* t))
      (broker--load-trusted-init configuration))
    (let ((*configuration* configuration))
      (main-authenticate
       (provider-bootstrap-configuration configuration)
       selection method)))
  nil)
