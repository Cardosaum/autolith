(in-package #:autolith)

;;;; -- Trusted Launcher Tool Tests --

(defclass test-broker-credential-store (broker-credential-store)
  ((value
    :initarg :value
    :reader test-broker-credential-store-value
    :documentation "A secret returned by the test store."))
  (:documentation "A custom broker credential store used by policy tests."))

(defmethod broker-credential-store-read
    ((store test-broker-credential-store) key)
  "Return the test value only for its declared key."
  (when (string= key "password")
    (test-broker-credential-store-value store)))

(-> test-broker-credential-stores () null)
(defun test-broker-credential-stores ()
  "Resolve declared store keys only inside an approved tool call."
  (with-test-environment (("AUTOLITH_TEST_STORE_KEY" "environment-secret"))
    (let ((*broker-credential-stores* nil)
          (*broker-registered-tools* nil)
          (reads 0)
          (captured-token nil)
          (frames nil))
      (test-assert
       (handler-case
           (progn
             (register-broker-credential-store
              "db" (make-instance 'test-broker-credential-store
                                  :value "database-secret"))
             nil)
         (broker-server-error () t))
       "agent-side code cannot register a credential store")
      (let ((*broker-registration-open-p* t))
        (register-broker-credential-store
         "db" (make-instance 'test-broker-credential-store
                             :value "database-secret"))
        (register-broker-credential-store
         "environment"
         (make-instance 'broker-environment-credential-store
                        :bindings '(("token" . "AUTOLITH_TEST_STORE_KEY"))))
        (test-assert
         (handler-case
             (progn
               (make-instance
                'broker-environment-credential-store
                :bindings '(("token" . "FIRST")
                            ("token" . "SECOND")))
               nil)
           (broker-server-error () t))
         "duplicate environment store keys are rejected")
        (test-assert
         (handler-case
             (progn
               (register-broker-credential-store
                "db" (make-instance 'test-broker-credential-store
                                    :value "other"))
               nil)
           (broker-server-error () t))
         "duplicate store names are rejected")
        (test-assert
         (handler-case
             (progn
               (register-broker-tool
                "db" "invalid"
                :description "Invalid credential declaration."
                :parameters (json-object "type" "object")
                :credentials '(("unknown" "password"))
                :handler (lambda (arguments)
                           (declare (ignore arguments)) "result"))
               nil)
           (broker-server-error () t))
         "tools cannot declare an unknown store")
        (register-broker-tool
         "db" "credential-check"
         :description "Check an approved broker credential."
         :parameters (json-object "type" "object")
         :credentials '(("db" "password") ("environment" "token"))
         :handler (lambda (arguments)
                    (declare (ignore arguments))
                    (incf reads)
                    (test-assert
                     (handler-case
                         (progn (broker-credential-value "db" "other") nil)
                       (broker-server-error () t))
                     "a handler cannot read an undeclared key")
                    (setf captured-token
                          (broker-credential-value "environment" "token"))
                    (format nil "~A ~A"
                            (broker-credential-value "db" "password")
                            captured-token))))
      (test-assert
       (handler-case
           (progn (broker-credential-value "db" "password") nil)
         (broker-server-error () t))
       "credentials are unavailable outside an approved handler")
      (platform-setenv "AUTOLITH_TEST_STORE_KEY" "rotated-secret")
      (let ((payload
              (json-encode
               (json-object "namespace" "db" "name" "credential-check"
                            "arguments" (json-object)))))
        (test-call-with-function-replacements
         (list (list 'broker-terminal-approve
                     (lambda (description)
                       (declare (ignore description)) nil)))
         (lambda ()
           (broker-registered-tools-call
            payload (lambda (frame) (push frame frames)))))
        (test-assert (zerop reads) "denial does not read credentials")
        (test-assert (equal frames '((:broker-result :status :denied)))
                     "denial returns no credential data")
        (setf frames nil)
        (test-call-with-function-replacements
         (list (list 'broker-terminal-approve
                     (lambda (description)
                       (declare (ignore description)) t)))
         (lambda ()
           (broker-registered-tools-call
            payload (lambda (frame) (push frame frames)))))
        (test-assert (= reads 1) "approval invokes the handler once")
        (test-assert (string= captured-token "rotated-secret")
                     "environment store values are read when used")
        (let ((output (apply #'concatenate 'string
                             (mapcar #'third
                                     (rest (butlast (nreverse frames)))))))
          (test-assert (not (search "database-secret" output))
                       "custom store secrets are redacted")
          (test-assert (not (search "rotated-secret" output))
                       "environment store secrets are redacted")
          (test-assert (search "[CREDENTIAL REDACTED]" output)
                       "redaction is visible to the agent")))))
  nil)

(-> test-broker-registered-tool-policy () null)
(defun test-broker-registered-tool-policy ()
  "Require trusted registration, exact calls, and one terminal decision."
  (let ((*broker-registered-tools* nil)
        (calls 0)
        (frames nil))
    (test-assert
     (handler-case
         (progn
           (register-broker-tool
            "db" "query"
            :description "Query a trusted database."
            :parameters (json-object "type" "object")
            :handler (lambda (arguments)
                       (declare (ignore arguments)) "result"))
           nil)
       (broker-server-error () t))
     "agent-side code cannot register a trusted handler")
    (let ((*broker-registration-open-p* t))
      (register-broker-tool
       "db" "query"
       :description "Query a trusted database."
       :parameters (json-object "type" "object")
       :handler (lambda (arguments)
                  (incf calls)
                  (format nil "rows: ~A" (json-get arguments "sql")))))
    (broker-registered-tools-discover
     "" (lambda (frame) (push frame frames)))
    (test-assert
     (equal (getf (first (getf (rest (first frames)) ':tools)) ':namespace)
            "db")
     "the broker advertises a launcher startup tool")
    (let ((payload
            (json-encode
             (json-object "namespace" "db" "name" "query"
                          "arguments" (json-object "sql" "select 1")))))
      (setf frames nil)
      (test-call-with-function-replacements
       (list (list 'broker-terminal-approve
                   (lambda (description)
                     (test-assert
                      (and (search "db.query" description)
                           (search "select 1" description))
                      "the approval shows the exact query")
                     nil)))
       (lambda ()
         (broker-registered-tools-call
          payload (lambda (frame) (push frame frames)))))
      (test-assert (equal frames '((:broker-result :status :denied)))
                   "a denial returns no handler data")
      (test-assert (zerop calls)
                   "a denial never invokes the database handler")
      (setf frames nil)
      (test-call-with-function-replacements
       (list (list 'broker-terminal-approve
                   (lambda (description)
                     (declare (ignore description)) t)))
       (lambda ()
         (broker-registered-tools-call
          payload (lambda (frame) (push frame frames)))))
      (test-assert (= calls 1)
                   "one approved request invokes the handler once")
      (test-assert
       (search "rows: select 1"
               (apply #'concatenate 'string
                      (mapcar #'third
                              (rest (butlast (nreverse frames))))))
       "the broker returns bounded handler output")
      (test-assert
       (handler-case
           (progn
             (broker-registered-tools-call
              (json-encode
               (json-object "namespace" "db" "name" "other"
                            "arguments" (json-object)))
              (lambda (frame) (declare (ignore frame))))
             nil)
         (broker-protocol-error () t))
       "an unregistered launcher target is rejected")))
  (with-test-environment (("AUTOLITH_TEST_DB_TOKEN" "broker-secret-value"))
    (let ((*broker-registered-tools* nil)
          (*broker-registration-open-p* t)
          (frames nil))
      (register-broker-tool
       "db" "redacted"
       :description "Return a redacted test value."
       :parameters (json-object "type" "object")
       :approval ':allow
       :credential-variables '("AUTOLITH_TEST_DB_TOKEN")
       :handler (lambda (arguments)
                  (declare (ignore arguments))
                  (uiop:getenv "AUTOLITH_TEST_DB_TOKEN")))
      (broker-registered-tools-call
       (json-encode
        (json-object "namespace" "db" "name" "redacted"
                     "arguments" (json-object)))
       (lambda (frame) (push frame frames)))
      (let ((output (apply #'concatenate 'string
                           (mapcar #'third
                                   (rest (butlast (nreverse frames)))))))
        (test-assert (not (search "broker-secret-value" output))
                     "configured credentials never leave the broker")
        (test-assert (search "[CREDENTIAL REDACTED]" output)
                     "the agent receives a redaction marker"))))
  nil)

(-> test-broker-registered-agent-route () null)
(defun test-broker-registered-agent-route ()
  "Keep launcher tool discovery and execution inside broker proxies."
  (with-test-configuration (configuration)
    (let* ((registry (make-instance 'tool-registry))
           (record (list ':namespace "db" ':name "query"
                         ':description "Query a trusted database."
                         ':parameters
                         (json-encode (json-object "type" "object"))))
           (called nil))
      (test-call-with-function-replacements
       (list
        (list 'broker-registered-agent--discover
              (lambda () (list record)))
        (list 'broker-registered-agent--call
              (lambda (tool arguments)
                (setf called (list (tool-canonical-name tool)
                                   (json-get arguments "sql")))
                (values "one row" t))))
       (lambda ()
         (broker-registered-agent-register registry)
         (let* ((tool (tool-registry-find registry "db" "query"))
                (context (test-mcp--context
                          configuration (conversation-create configuration)
                          registry))
                (result (tool-execute
                         tool context (json-object "sql" "select 1"))))
           (test-assert (typep tool 'broker-registered-agent-tool)
                        "the agent sees a launcher tool proxy")
           (test-assert (tool-result-success-p result)
                        "the launcher result reaches the agent")
           (test-assert (equal called '("db.query" "select 1"))
                        "the agent sends exact arguments to the broker"))))))
  nil)
