(in-package #:autolith)

;;;; -- Trusted Launcher Tools --

(defclass broker-registered-tool (tool)
  ((handler
    :initarg :handler
    :reader broker-registered-tool-handler
    :type function
    :documentation "The trusted launcher callback for one exact operation.")
   (approval
    :initarg :approval
    :reader broker-registered-tool-approval
    :type keyword
    :documentation "The trusted terminal approval policy.")
   (credential-variables
    :initarg :credential-variables
    :reader broker-registered-tool-credential-variables
    :type list
    :documentation "Host variables whose values are redacted from the result."))
  (:documentation "One launcher-owned tool registered before the broker listens."))

(defvar *broker-registered-tools* nil
  "Trusted launcher tool registrations in the current broker process.")

(defvar *broker-registration-open-p* nil
  "True only while the broker loads its private initialization file.")

(-> register-broker-tool
    (string string &key (:description string) (:parameters json-object)
                        (:handler function) (:approval keyword)
                        (:credential-variables list))
    broker-registered-tool)
(defun register-broker-tool
    (namespace name &key description parameters handler
                         (approval ':prompt) credential-variables)
  "Register one fixed launcher callback during trusted broker initialization.

HANDLER receives one JSON argument object and returns bounded text. Every
call is authorized by the broker, independently of agent tool permissions."
  (unless *broker-registration-open-p*
    (error 'broker-server-error
           :message "Broker tools can be registered only during trusted startup."
           :reason ':configuration))
  (unless (and (non-empty-string-p namespace)
               (<= (length namespace) 128)
               (non-empty-string-p name)
               (<= (length name) 256)
               (non-empty-string-p description)
               (<= (length description) 8192)
               (json-object-p parameters)
               (<= (length (json-encode parameters)) (* 1024 1024))
               (functionp handler)
               (member approval '(:prompt :allow :deny))
               (listp credential-variables)
               (every (lambda (variable)
                        (and (non-empty-string-p variable)
                             (<= (length variable) 128)))
                      credential-variables))
    (error 'broker-server-error
           :message "A trusted broker tool registration is invalid."
           :reason ':configuration))
  (let ((tool (make-instance
               'broker-registered-tool
               :namespace namespace :name name
               :description description :parameters parameters
               :handler handler :approval approval
               :credential-variables credential-variables)))
    (when (find (tool-canonical-name tool) *broker-registered-tools*
                :test #'string= :key #'tool-canonical-name)
      (error 'broker-server-error
             :message "A trusted broker tool name is registered twice."
             :reason ':configuration))
    (setf *broker-registered-tools*
          (append *broker-registered-tools* (list tool)))
    tool))

(-> broker-registered-tools-discover (string function) null)
(defun broker-registered-tools-discover (source write-frame)
  "Send detached metadata for startup-registered launcher tools."
  (unless (string= source "")
    (error 'broker-protocol-error
           :message "Trusted tool discovery takes no payload."
           :reason ':payload))
  (funcall
   write-frame
   (list ':broker-result ':status ':registered-tools
         ':tools
         (mapcar (lambda (tool)
                   (list ':namespace (tool-namespace tool)
                         ':name (tool-name tool)
                         ':description (tool-description tool)
                         ':parameters (json-encode (tool-parameters tool))))
                 *broker-registered-tools*)))
  nil)

(-> broker-registered-tools--payload (string) json-object)
(defun broker-registered-tools--payload (source)
  "Require one exact registered identity and a JSON argument object."
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
             :message "The trusted tool request is invalid."
             :reason ':payload))
    value))

(-> broker-registered-tools-call (string function) null)
(defun broker-registered-tools-call (source write-frame)
  "Authorize and run one startup-registered callback in the broker image."
  (let* ((payload (broker-registered-tools--payload source))
         (namespace (json-get payload "namespace"))
         (name (json-get payload "name"))
         (arguments (json-get payload "arguments"))
         (tool (find-if
                (lambda (candidate)
                  (and (string= namespace (tool-namespace candidate))
                       (string= name (tool-name candidate))))
                *broker-registered-tools*)))
    (unless tool
      (error 'broker-protocol-error
             :message "The trusted tool is not registered."
             :reason ':target))
    (unless (case (broker-registered-tool-approval tool)
              (:allow t)
              (:prompt
               (broker-terminal-approve
                (format nil "Launcher tool: ~A~%Arguments: ~A"
                        (tool-canonical-name tool)
                        (json-encode arguments)))))
      (funcall write-frame '(:broker-result :status :denied))
      (return-from broker-registered-tools-call nil))
    (let* ((result (funcall (broker-registered-tool-handler tool) arguments))
           (secrets (remove nil
                            (mapcar #'uiop:getenv
                                    (broker-registered-tool-credential-variables
                                     tool))))
           (safe-result
             (and (stringp result)
                  (redact-exact-string-values
                   result secrets
                   (safe-redaction-marker "[CREDENTIAL REDACTED]"
                                          secrets)))))
      (unless (and safe-result
                   (<= (length safe-result) (* 1024 1024)))
        (error 'broker-protocol-error
               :message "The trusted tool returned invalid or oversized text."
               :reason ':response))
      (funcall write-frame '(:broker-result :status :open :code 200))
      (with-input-from-string (stream safe-result)
        (broker-provider--copy-stream stream write-frame))))
  nil)
