(in-package #:autolith)

;;;; -- Trusted Launcher Tool Tests --

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
