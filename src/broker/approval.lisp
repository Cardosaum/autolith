(in-package #:autolith)

;;;; -- Trusted Terminal Approval --

(defparameter *broker-approval-maximum-bytes* 4096
  "The largest complete action description shown by the trusted terminal.")

(defvar *broker-approval-lock* (make-lock "Broker terminal approval")
  "Serialize prompts so one real terminal sees only one request at a time.")

(-> broker-approval--socket-path () (option pathname))
(defun broker-approval--socket-path ()
  "Return the launcher's private terminal relay socket, or NIL if unavailable."
  (let* ((value (uiop:getenv "AUTOLITH_BROKER_APPROVAL_SOCKET"))
         (path (and value (pathname value)))
         (directory (and path (uiop:pathname-directory-pathname path)))
         (component (and directory
                         (first (last (pathname-directory directory)))))
         (root (platform-launcher-root *platform* ':state)))
    (when (and path
               (uiop:absolute-pathname-p path)
               (uiop:subpathp path root)
               (string= (file-namestring path) "control.sock")
               (stringp component)
               (<= (length "session.") (length component))
               (string= component "session."
                        :end1 (length "session.")))
      (let ((directory-status (platform-path-status *platform* directory))
            (socket-status (platform-path-status *platform* path)))
        (when (and directory-status socket-status
                   (eq (platform-file-status-kind directory-status) ':directory)
                   (platform-file-status-owned-p directory-status)
                   (platform-file-status-private-p directory-status)
                   (eq (platform-file-status-kind socket-status) ':socket)
                   (platform-file-status-owned-p socket-status)
                   (platform-file-status-private-p socket-status))
          path)))))

(-> broker-approval--send (pathname string) boolean)
(defun broker-approval--send (path description)
  "Ask the trusted PTY relay to show DESCRIPTION and return its one-bit answer."
  (let ((socket nil)
        (stream nil)
        (octets (sb-ext:string-to-octets description :external-format ':utf-8)))
    (unless (<= 1 (length octets) *broker-approval-maximum-bytes*)
      (return-from broker-approval--send nil))
    (unwind-protect
         (handler-case
             (progn
               (setf socket (platform-connect-local *platform* path)
                     stream (sb-bsd-sockets:socket-make-stream
                             socket :input t :output t
                             :element-type '(unsigned-byte 8)
                             :buffering ':none :timeout 120))
               (let ((length (length octets)))
                 (write-byte (ldb (byte 8 24) length) stream)
                 (write-byte (ldb (byte 8 16) length) stream)
                 (write-byte (ldb (byte 8 8) length) stream)
                 (write-byte (ldb (byte 8 0) length) stream))
               (write-sequence octets stream)
               (finish-output stream)
               (eql (read-byte stream nil nil) (char-code #\1)))
           (error ()
             nil))
      (when stream
        (ignore-errors (close stream)))
      (when socket
        (ignore-errors (sb-bsd-sockets:socket-close socket))))))

(-> broker-terminal-approve (string) boolean)
(defun broker-terminal-approve (description)
  "Require a fresh launcher-terminal challenge for one complete action."
  (with-lock-held (*broker-approval-lock*)
    (let ((path (broker-approval--socket-path)))
      (and path
           (broker-approval--send path description)
           t))))
