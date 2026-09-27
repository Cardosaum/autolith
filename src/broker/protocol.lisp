(in-package #:autolith)

;;;; -- Credential Broker Protocol --

;;; One connection carries one request and its response frames. The broker
;;; accepts only the operations below, then each handler validates its payload
;;; before performing any credentialed work. Neither a URL nor a header is an
;;; authority granted by this envelope.

(defparameter *broker-protocol-version* 1
  "The credential broker wire protocol version.")

(defparameter *broker-maximum-frame-size* (* 16 1024 1024)
  "The largest broker request or response frame in octets.")

(defparameter *broker-operations*
  '(:provider-turn :provider-compaction :provider-models
    :provider-authenticate :mcp-discover :mcp-call :registered-tool-call)
  "The exact credentialed operations accepted by the broker envelope.")

(define-condition broker-protocol-error (autolith-error)
  ((reason
    :initarg :reason
    :reader broker-protocol-error-reason
    :type keyword
    :documentation "The malformed broker frame or request category."))
  (:documentation "An untrusted broker request failed wire validation."))

(-> broker-request-validate (t) list)
(defun broker-request-validate (request)
  "Return REQUEST after validating its exact, flat broker envelope.

The target is an identifier in trusted broker configuration, never a path,
command, endpoint, header, or credential. The operation handler separately
validates the bounded payload for its own schema."
  (unless (and (listp request)
               (eql (ignore-errors (list-length request)) 9)
               (eq (first request) ':broker-request)
               (eq (second request) ':version)
               (eql (third request) *broker-protocol-version*)
               (eq (fourth request) ':operation)
               (member (fifth request) *broker-operations*)
               (eq (sixth request) ':target)
               (non-empty-string-p (seventh request))
               (<= (length (seventh request)) 128)
               (every (lambda (character)
                        (or (alphanumericp character)
                            (find character "-_./")))
                      (seventh request))
               (eq (eighth request) ':payload)
               (stringp (ninth request)))
    (error 'broker-protocol-error
           :message "The broker request has an invalid operation or envelope."
           :reason ':request))
  request)

(-> broker-read-request (stream) (option list))
(defun broker-read-request (stream)
  "Read one bounded broker request from STREAM, or NIL at clean EOF."
  (handler-case
      (let ((request
              (management-repl-read-frame stream *broker-maximum-frame-size*)))
        (unless (eq request ':end-of-input)
          (broker-request-validate request)))
    (management-repl-protocol-error ()
      (error 'broker-protocol-error
             :message "The broker request frame is malformed or oversized."
             :reason ':frame))))

(-> broker-write-frame (stream t) null)
(defun broker-write-frame (stream value)
  "Write one bounded broker response frame to STREAM."
  (handler-case
      (management-repl-write-frame stream value *broker-maximum-frame-size*)
    (management-repl-protocol-error ()
      (error 'broker-protocol-error
             :message "The broker response frame is oversized."
             :reason ':frame)))
  nil)
