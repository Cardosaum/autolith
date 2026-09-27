(in-package #:autolith)

;;;; -- Brokered MCP Tests --

(-> broker-mcp-tests--body (list) json-object)
(defun broker-mcp-tests--body (frames)
  "Decode one complete bounded JSON result from broker response FRAMES."
  (test-assert (equal (first frames)
                      '(:broker-result :status :open :code 200))
               "MCP result opens one bounded broker stream")
  (test-assert (equal (first (last frames)) '(:broker-end))
               "MCP result ends with the protocol terminal frame")
  (json-decode
   (apply #'concatenate 'string
          (mapcar #'third (subseq frames 1 (1- (length frames)))))))

(-> test-broker-mcp-policy () null)
(defun test-broker-mcp-policy ()
  "Test trusted discovery, automatic reads, explicit approval, and denial."
  (with-test-configuration (configuration)
    (multiple-value-bind (manager transport)
        (test-mcp--manager configuration)
      (let* ((service (make-instance 'broker-mcp-service
                                     :configuration configuration))
             (registry (make-instance 'tool-registry))
             (discovery nil)
             (frames nil))
        (unwind-protect
             (progn
               (mcp-tool-registry-register-manager registry manager)
               (setf (broker-mcp-service-manager service) manager
                     (broker-mcp-service-registry service) registry)
               (broker-mcp-discover service ""
                                    (lambda (frame) (push frame discovery)))
               (test-assert
                (some (lambda (record)
                        (string= (getf record ':raw-tool) "read file"))
                      (getf (rest (first discovery)) ':tools))
                "broker discovery advertises an exact registered tool")
               (let* ((tool (test-mcp--tool-with-raw-name registry "read file"))
                      (payload
                        (json-encode
                         (json-object
                          "namespace" (tool-namespace tool)
                          "name" (tool-name tool)
                          "arguments" (json-object "value" "fixture")))))
                 (test-call-with-function-replacements
                  (list (list 'broker-terminal-approve
                              (lambda (description)
                                (declare (ignore description))
                                (error "A trusted read must not prompt."))))
                  (lambda ()
                    (broker-mcp-call service payload
                                     (lambda (frame) (push frame frames)))))
                 (let* ((body (broker-mcp-tests--body (nreverse frames)))
                        (result (json-get body "result")))
                   (test-assert (string= (json-get body "kind") "tool")
                                "the broker returns a portable tool result")
                   (test-assert
                    (= (json-get (json-get result "structuredContent") "answer")
                       42)
                    "structured MCP content survives the broker boundary")))
               (let* ((tool (test-mcp--tool-with-raw-name registry "mutate"))
                      (payload
                        (json-encode
                         (json-object
                          "namespace" (tool-namespace tool)
                          "name" (tool-name tool)
                          "arguments" (json-object "value" "mutation"))))
                      (before (length (test-mcp-transport-requests transport))))
                 (setf frames nil)
                 (test-call-with-function-replacements
                  (list (list 'broker-terminal-approve
                              (lambda (description)
                                (test-assert
                                 (and (search "MCP action:" description)
                                      (search "mutation" description))
                                 "the trusted prompt shows the exact operation")
                                nil)))
                  (lambda ()
                    (broker-mcp-call service payload
                                     (lambda (frame) (push frame frames)))))
                 (test-assert (equal (nreverse frames)
                                     '((:broker-result :status :denied)))
                              "denied MCP calls return no server data")
                 (test-assert
                  (= (length (test-mcp-transport-requests transport)) before)
                  "denial sends no request to the MCP server")
                 (setf frames nil)
                 (test-call-with-function-replacements
                  (list (list 'broker-terminal-approve
                              (lambda (description)
                                (declare (ignore description))
                                t)))
                  (lambda ()
                    (broker-mcp-call service payload
                                     (lambda (frame) (push frame frames)))))
                 (test-assert (string= (json-get
                                        (broker-mcp-tests--body (nreverse frames))
                                        "kind")
                                       "tool")
                              "a trusted approval permits one exact MCP call"))
               (test-assert
                (handler-case
                    (progn
                      (broker-mcp-call
                       service
                       (json-encode
                        (json-object "namespace" "mcp__forged"
                                     "name" "query"
                                     "arguments" (json-object)))
                       (lambda (frame) (declare (ignore frame))))
                      nil)
                  (broker-protocol-error () t))
                "an unregistered MCP target is rejected"))
          (broker-mcp-service-close service)))))
  nil)

(-> test-broker-mcp-agent-route () null)
(defun test-broker-mcp-agent-route ()
  "Keep agent discovery and execution on the broker route in active sandbox."
  (with-test-configuration (configuration)
    (let* ((registry (make-instance 'tool-registry))
           (record (list ':namespace "mcp__test_server"
                         ':name "read_file"
                         ':description "Read a test file."
                         ':parameters
                         (json-encode
                          (json-object "type" "object"))
                         ':server "Test Server"
                         ':raw-tool "read file"
                         ':read-only-p t
                         ':child-safe-p t))
           (called nil))
      (with-test-environment (("AUTOLITH_AGENT_SANDBOX" "active"))
        (test-call-with-function-replacements
         (list
          (list 'broker-mcp-agent--discover
                (lambda () (list record)))
          (list 'broker-registered-agent--discover
                (lambda () nil))
          (list 'mcp-manager-create
                (lambda (configuration)
                  (declare (ignore configuration))
                  (error "The sandbox must not create an MCP client.")))
          (list 'mcp-configuration-load
                (lambda (configuration)
                  (declare (ignore configuration))
                  (error "The sandbox must not read MCP credentials.")))
          (list 'user-init-load
                (lambda (configuration)
                  (declare (ignore configuration))
                  nil))
          (list 'broker-mcp-agent--call
                (lambda (tool arguments)
                  (setf called (list (tool-canonical-name tool)
                                     (json-get arguments "value")))
                  (values
                   (json-object
                    "kind" "tool"
                    "result"
                    (json-object
                     "content"
                     (json-array
                      (json-object "type" "text" "text" "result"))
                     "isError" *json-decoded-false*))
                   t))))
         (lambda ()
           (application--load-extension-configuration configuration)
           (multiple-value-bind (augmented manager)
               (mcp-tool-registry-augment registry configuration)
             (test-assert (eq augmented registry)
                          "the sandbox keeps its agent registry")
             (test-assert (null manager)
                          "the sandbox has no direct MCP manager"))
           (let* ((tool (tool-registry-find
                         registry "mcp__test_server" "read_file"))
                  (context (test-mcp--context
                            configuration
                            (conversation-create configuration)
                            registry))
                  (result (tool-execute
                           tool context (json-object "value" "query"))))
             (test-assert (typep tool 'broker-mcp-tool)
                          "the agent receives a broker proxy")
             (test-assert (tool-result-success-p result)
                          "the brokered result renders successfully")
             (test-assert (search "result" (tool-result-content result))
                          "the MCP content reaches the agent")
             (test-assert
              (equal called '("mcp__test_server.read_file" "query"))
              "the agent sends exact arguments to its broker")))))))
  nil)
