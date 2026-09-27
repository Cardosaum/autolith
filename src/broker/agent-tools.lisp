(in-package #:autolith)

;;;; -- Agent Launcher Tool Route --

(defclass broker-registered-agent-tool (broker-mcp-tool)
  ()
  (:documentation "A launcher-defined tool executed only by the trusted broker."))

(-> broker-registered-agent--discover () list)
(defun broker-registered-agent--discover ()
  "Receive bounded launcher-owned tool metadata from the broker."
  (broker-client-request
   ':registered-tool-discover "registered" ""
   (lambda (stream)
     (let ((frame (management-repl-read-frame
                   stream *broker-maximum-frame-size*)))
       (unless (and (listp frame)
                    (eql (ignore-errors (list-length frame)) 5)
                    (equal (subseq frame 0 4)
                           '(:broker-result :status :registered-tools :tools))
                    (listp (fifth frame))
                    (<= (length (fifth frame)) 1024))
         (error 'broker-protocol-error
                :message "The broker returned invalid launcher tool metadata."
                :reason ':response))
       (fifth frame)))))

(-> broker-registered-agent-register (tool-registry) tool-registry)
(defun broker-registered-agent-register (registry)
  "Replace launcher tool proxies after validating every discovered schema."
  (let ((tools
          (mapcar (lambda (record)
                    (let ((tool (broker-mcp-agent--tool record)))
                      (when (broker-mcp-tool-server tool)
                        (error 'broker-protocol-error
                               :message "A launcher tool has MCP server metadata."
                               :reason ':response))
                      (change-class tool 'broker-registered-agent-tool)))
                  (broker-registered-agent--discover)))
        (names (make-hash-table :test #'equal)))
    (dolist (tool (tool-registry-tools registry))
      (unless (typep tool 'broker-registered-agent-tool)
        (setf (gethash (tool-canonical-name tool) names) t)))
    (dolist (tool tools)
      (when (gethash (tool-canonical-name tool) names)
        (error 'broker-protocol-error
               :message "A launcher tool conflicts with an agent tool."
               :reason ':response))
      (setf (gethash (tool-canonical-name tool) names) t))
    (tool-registry-delete-if
     registry (lambda (tool) (typep tool 'broker-registered-agent-tool)))
    (dolist (tool tools)
      (tool-registry-register registry tool)))
  registry)

(-> broker-registered-agent--call (broker-registered-agent-tool json-object)
    (values (option string) boolean))
(defun broker-registered-agent--call (tool arguments)
  "Call one exact launcher tool and return its approved text or denial."
  (broker-client-request
   ':registered-tool-call "registered"
   (json-encode
    (json-object "namespace" (tool-namespace tool)
                 "name" (tool-name tool)
                 "arguments" arguments))
   (lambda (stream)
     (let ((frame (management-repl-read-frame
                   stream *broker-maximum-frame-size*)))
       (when (equal frame '(:broker-result :status :denied))
         (return-from broker-registered-agent--call (values nil nil)))
       (unless (equal frame '(:broker-result :status :open :code 200))
         (error 'broker-protocol-error
                :message "The broker returned an invalid launcher tool response."
                :reason ':response))
       (values
        (broker-mcp-agent--read-body
         (make-instance 'broker-response-stream :source stream))
        t)))))

(defmethod tool-execute
    ((tool broker-registered-agent-tool)
     (context tool-context)
     (arguments hash-table))
  "Use the broker's trusted handler and terminal approval for this call."
  (declare (ignore context))
  (multiple-value-bind (content allowed-p)
      (broker-registered-agent--call tool arguments)
    (if allowed-p
        (tool-success content)
        (tool-failure "The trusted launcher denied this tool call."))))
