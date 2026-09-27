(in-package #:autolith)

;;;; -- Trusted Broker Image Entry --

(defparameter *broker-image-argument* "--autolith-internal-broker"
  "The stable launcher's private entry into the preloaded broker image.")

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

(-> broker--handle-request (configuration list function) null)
(defun broker--handle-request (configuration request write-frame)
  "Dispatch one validated request using only trusted broker configuration."
  (let ((operation (getf (rest request) ':operation))
        (target (getf (rest request) ':target))
        (payload (getf (rest request) ':payload)))
    (case operation
      (:provider-turn
       (broker-provider-stream configuration target payload write-frame))
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
         (launcher-data (config :data-root configuration)))
    (unless (uiop:subpathp socket-pathname launcher-data)
      (error 'broker-server-error
             :message "The broker socket is outside the launcher data root."
             :reason ':path))
    (configuration-ensure-directories configuration)
    (broker--load-trusted-init configuration)
    (provider-bootstrap-configuration configuration)
    (let ((*configuration* configuration)
          (server
            (broker-server-create
             socket-pathname
             (lambda (request write-frame)
               (broker--handle-request configuration request write-frame)))))
      (broker-server-serve server)))
  nil)
