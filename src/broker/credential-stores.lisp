(in-package #:autolith)

;;;; -- Trusted Broker Credential Stores --

(defclass broker-credential-store ()
  ()
  (:documentation "A launcher-owned source of named credentials for broker tools."))

(defclass broker-environment-credential-store (broker-credential-store)
  ((bindings
    :initarg :bindings
    :reader broker-environment-credential-store-bindings
    :type list
    :documentation "Pairs of public credential keys and host variable names."))
  (:documentation "Resolve explicitly named host variables at request time."))

(defmethod initialize-instance :after
    ((store broker-environment-credential-store) &key)
  "Reject malformed or repeated environment bindings before registration."
  (let ((bindings (broker-environment-credential-store-bindings store)))
    (unless (and (listp bindings)
                 (every (lambda (binding)
                          (and (consp binding)
                               (non-empty-string-p (first binding))
                               (<= (length (first binding)) 128)
                               (non-empty-string-p (rest binding))
                               (<= (length (rest binding)) 128)))
                        bindings)
                 (= (length bindings)
                    (length (remove-duplicates bindings :test #'string=
                                               :key #'first))))
      (error 'broker-server-error
             :message "A broker environment credential binding is invalid."
             :reason ':configuration))))

(defgeneric broker-credential-store-read (store key)
  (:documentation "Return the secret string for KEY, or NIL when unavailable."))

(defmethod broker-credential-store-read
    ((store broker-environment-credential-store) key)
  "Read one explicitly bound host variable without caching its value."
  (let ((binding (assoc key (broker-environment-credential-store-bindings store)
                        :test #'string=)))
    (when binding
      (uiop:getenv (rest binding)))))

(defvar *broker-credential-stores* nil
  "Named stores registered by the launcher's private initialization file.")

(defvar *broker-registration-open-p* nil
  "True only while the broker loads its private initialization file.")

(defvar *broker-authorized-credentials* nil
  "Credential keys available to the currently approved broker tool call.")

(defvar *broker-used-credential-values* nil
  "Secret values read during the current broker tool call for response redaction.")

(-> register-broker-credential-store (string broker-credential-store)
    broker-credential-store)
(defun register-broker-credential-store (name store)
  "Register STORE under NAME during trusted broker initialization."
  (unless *broker-registration-open-p*
    (error 'broker-server-error
           :message "Credential stores can be registered only during trusted startup."
           :reason ':configuration))
  (unless (and (non-empty-string-p name)
               (<= (length name) 128)
               (not (assoc name *broker-credential-stores* :test #'string=)))
    (error 'broker-server-error
           :message "A trusted credential store name is invalid or duplicated."
           :reason ':configuration))
  (push (cons name store) *broker-credential-stores*)
  store)

(-> broker-credential-store--resolve (string string) (option string))
(defun broker-credential-store--resolve (store-name key)
  "Resolve a named broker store key without exposing the store to the agent."
  (let ((entry (assoc store-name *broker-credential-stores* :test #'string=)))
    (when entry
      (let ((value (broker-credential-store-read (rest entry) key)))
        (when (and (non-empty-string-p value)
                   (<= (length value) 65536))
          value)))))

(-> broker-credential-value (string string) string)
(defun broker-credential-value (store-name key)
  "Read an approved tool's declared credential and retain it for redaction."
  (unless (member (list store-name key) *broker-authorized-credentials*
                  :test #'equal)
    (error 'broker-server-error
           :message "The broker tool did not declare this credential."
           :reason ':credential))
  (let ((value (broker-credential-store--resolve store-name key)))
    (unless value
      (error 'broker-server-error
             :message "The declared broker credential is unavailable."
             :reason ':credential))
    (pushnew value *broker-used-credential-values* :test #'string=)
    value))
