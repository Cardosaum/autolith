(in-package #:autolith)

;;;; -- Credential Broker Protocol Tests --

(-> test-broker-protocol () null)
(defun test-broker-protocol ()
  "Test exact broker envelopes and bounded safe framing."
  (let* ((request '(:broker-request :version 2
                    :operation :provider-turn
                    :target "chatgpt"
                    :payload "{}" :capability "launch-token"))
         (output (make-in-memory-output-stream)))
    (broker-write-frame output request)
    (test-assert
     (equal request
            (broker-read-request
             (flexi-streams:make-in-memory-input-stream
              (get-output-stream-sequence output))))
     "broker requests round-trip through bounded framing"))
  (dolist (request
           (list '(:broker-request :version 1
                   :operation :provider-turn :target "chatgpt" :payload "{}"
                   :capability "launch-token")
                 '(:broker-request :version 2
                   :operation :read-secret :target "chatgpt" :payload "{}"
                   :capability "launch-token")
                 '(:broker-request :version 2
                   :operation :provider-turn :target "" :payload "{}"
                   :capability "launch-token")
                 '(:broker-request :version 2
                   :operation :provider-turn :target "chatgpt" :payload "{}"
                   :capability "launch-token" :endpoint "https://example.invalid")
                 '(:broker-request :version 2
                   :operation :provider-turn :target "chatgpt"
                   :payload "{}" :capability "launch-token" . :extra)))
    (test-assert
     (handler-case
         (progn (broker-request-validate request) nil)
       (broker-protocol-error () t))
     "broker rejects an invalid or extended request envelope"))
  (let ((output (make-in-memory-output-stream)))
    (management-repl-write-frame
     output '(:broker-request :version 2
              :operation :provider-turn :target "chatgpt"
              :payload "#.(error \"unsafe\")" :capability "launch-token")
     4096)
    (test-assert
     (equal '(:broker-request :version 2
              :operation :provider-turn :target "chatgpt"
              :payload "#.(error \"unsafe\")" :capability "launch-token")
            (broker-read-request
             (flexi-streams:make-in-memory-input-stream
              (get-output-stream-sequence output))))
     "broker treats payload source as data"))
  (let* ((source "#.(error \"unsafe\")")
         (body (sb-ext:string-to-octets source :external-format ':utf-8))
         (frame (concatenate '(vector (unsigned-byte 8))
                             (management-repl--integer->header (length body))
                             body)))
    (test-assert
     (handler-case
         (progn
           (broker-read-request
            (flexi-streams:make-in-memory-input-stream frame))
           nil)
       (broker-protocol-error () t))
     "broker rejects read-time evaluation in an untrusted frame"))
  (let ((cycle (list ':broker-request ':version 2 ':operation
                     ':provider-turn ':target "chatgpt" ':payload "{}"
                     ':capability "launch-token")))
    (setf (rest (last cycle)) cycle)
    (test-assert
     (handler-case
         (progn (broker-request-validate cycle) nil)
       (broker-protocol-error () t))
     "broker rejects circular request lists"))
  (test-assert
   (handler-case
       (progn
         (broker-read-request
          (flexi-streams:make-in-memory-input-stream
           (make-array 4 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 0 0 1))))
         nil)
     (broker-protocol-error (condition)
       (eq (broker-protocol-error-reason condition) ':frame)))
   "broker rejects an oversized frame before allocation")
  nil)
