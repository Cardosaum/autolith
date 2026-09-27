(in-package #:autolith)

;;;; -- Credential Broker Socket Tests --

(-> broker-server-test--connect (pathname) (values sb-bsd-sockets:socket stream))
(defun broker-server-test--connect (pathname)
  "Connect to PATHNAME and return its socket and octet stream."
  (let* ((socket (platform-connect-local *platform* pathname))
         (stream (sb-bsd-sockets:socket-make-stream
                  socket :input t :output t
                  :element-type '(unsigned-byte 8)
                  :buffering ':none :timeout 2)))
    (values socket stream)))

(-> test-broker-server-lifecycle () null)
(defun test-broker-server-lifecycle ()
  "Test private binding, request service, fail-closed errors, and cleanup."
  (with-platform-capability (':local-sockets "broker socket lifecycle")
    (let* ((root (platform-make-temporary-directory
                  *platform* (uiop:temporary-directory) "autolith-broker-test-"))
           (pathname (merge-pathnames "broker.sock" root))
           (server
             (broker-server-create
              pathname
              (lambda (request write-frame)
                (funcall write-frame
                         (list ':broker-result ':status ':ok
                               :target (getf (rest request) ':target))))))
           (thread nil))
      (unwind-protect
           (progn
             (with-open-file (stream pathname
                                     :direction ':output
                                     :if-does-not-exist ':create)
               (write-string "occupied" stream))
             (test-assert
              (handler-case
                  (progn (broker-server-start server) nil)
                (broker-server-error (condition)
                  (eq (broker-server-error-reason condition) ':path)))
              "broker refuses an occupied endpoint")
             (test-assert (probe-file pathname)
                          "broker leaves the occupied path intact")
             (delete-file pathname)
             (broker-server-start server)
             (setf thread (make-thread
                           (lambda () (broker-server-serve server))
                           :name "Broker server test"))
             (test-assert (broker-server-listener server)
                          "broker starts its private listener")
             (let ((status (platform-path-status *platform* pathname)))
               (test-assert
                (and status
                     (eq (platform-file-status-kind status) ':socket)
                     (platform-file-status-private-p status))
                "broker socket is private"))
             (multiple-value-bind (socket stream)
                 (broker-server-test--connect pathname)
               (unwind-protect
                    (progn
                      (broker-write-frame
                       stream
                       '(:broker-request :version 1
                         :operation :provider-turn
                         :target "chatgpt" :payload "{}"))
                      (test-assert
                       (equal (management-repl-read-frame
                               stream *broker-maximum-frame-size*)
                              '(:broker-result :status :ok :target "chatgpt"))
                       "broker serves a validated request"))
                 (ignore-errors (close stream))
                 (ignore-errors (sb-bsd-sockets:socket-close socket))))
             (multiple-value-bind (socket stream)
                 (broker-server-test--connect pathname)
               (unwind-protect
                    (progn
                      (broker-write-frame
                       stream
                       '(:broker-request :version 1
                         :operation :read-secret
                         :target "chatgpt" :payload "{}"))
                      (test-assert
                       (equal (management-repl-read-frame
                               stream *broker-maximum-frame-size*)
                              '(:broker-result :status :failed))
                       "broker returns no detail for an invalid request"))
                 (ignore-errors (close stream))
                 (ignore-errors (sb-bsd-sockets:socket-close socket)))))
        (broker-server-close server)
        (when thread (join-thread thread))
        (test-assert (null (platform-path-status *platform* pathname))
                     "broker removes its own socket")
        (platform-delete-directory-tree *platform* root
                                        :validate t
                                        :if-does-not-exist ':ignore))))
  nil)
