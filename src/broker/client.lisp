(in-package #:autolith)

;;;; -- Credential Broker Client --

(defparameter *broker-socket-variable* "AUTOLITH_BROKER_SOCKET"
  "The trusted broker socket pathname supplied by the stable launcher.")

(define-condition broker-unavailable (autolith-error)
  ((reason
    :initarg :reason
    :reader broker-unavailable-reason
    :type keyword
    :documentation "The stage at which the broker request failed."))
  (:documentation "The agent could not complete a request through its broker."))

(-> broker-socket-pathname () pathname)
(defun broker-socket-pathname ()
  "Return the launcher's broker socket, or fail when it was not supplied."
  (let ((value (uiop:getenv *broker-socket-variable*)))
    (unless (and value
                 (plusp (length value))
                 (uiop:absolute-pathname-p (pathname value)))
      (error 'broker-unavailable
             :message "The credential broker socket is unavailable."
             :reason ':configuration))
    (pathname value)))

(-> broker-client-request
    (keyword string string function &key (:socket-pathname pathname))
    t)
(defun broker-client-request
    (operation target payload response-function &key
                                              (socket-pathname
                                                (broker-socket-pathname)))
  "Send one validated request and let RESPONSE-FUNCTION consume its reply.

The function receives a bounded binary stream. It must finish reading before
returning, because each connection owns exactly one request."
  (broker-request-validate
   (list ':broker-request ':version *broker-protocol-version*
         ':operation operation ':target target ':payload payload))
  (let ((socket nil)
        (stream nil))
    (unwind-protect
         (handler-case
             (progn
               (setf socket (platform-connect-local *platform* socket-pathname)
                     stream (sb-bsd-sockets:socket-make-stream
                             socket :input t :output t
                             :element-type '(unsigned-byte 8)
                             :buffering ':none :timeout 300))
               (broker-write-frame
                stream
                (list ':broker-request ':version *broker-protocol-version*
                      ':operation operation ':target target ':payload payload))
               (funcall response-function stream))
           (broker-protocol-error (condition)
             (error condition))
           (error ()
             (error 'broker-unavailable
                    :message "The credential broker request failed."
                    :reason ':transport)))
      (when stream
        (ignore-errors (close stream)))
      (when socket
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))
