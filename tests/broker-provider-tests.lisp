(in-package #:autolith)

;;;; -- Trusted Provider Transport Tests --

(-> test-broker-provider-transport () null)
(defun test-broker-provider-transport ()
  "Test trusted provider selection, credential scope, and streamed output."
  (with-test-configuration (configuration)
    (let* ((registration (provider-registration-find "chatgpt"))
           (model (provider-model-name
                   (first (provider-registration-models registration))))
           (payload
             (json-encode
              (json-object "model" model
                           "conversation_id" "broker-test-1"
                           "prompt_cache_key" nil
                           "turn_state" nil
                           "force_refresh" *json-decoded-false*
                           "request" (json-object "model" model))))
           (credentials
             (make-instance 'oauth-credentials
                            :access-token "broker-secret-token"
                            :refresh-token nil
                            :id-token nil
                            :account-id "broker-account"
                            :expires-at nil
                            :source-path #P"/private/tmp/broker-test-auth"))
           (frames nil)
           (captured-headers nil))
      (test-call-with-function-replacements
       (list
        (list 'call-with-credentials
              (lambda (manager function &key force-refresh)
                (declare (ignore manager force-refresh))
                (funcall function credentials)))
        (list 'dexador:post
              (lambda (url &key headers content &allow-other-keys)
                (declare (ignore url content))
                (setf captured-headers headers)
                (values (make-string-input-stream
                         (format nil "data: first~%~%"))
                        200 nil))))
       (lambda ()
         (broker-provider-stream
          configuration "chatgpt" payload
          (lambda (frame) (push frame frames)))))
      (setf frames (nreverse frames))
      (test-assert
       (equal (first frames)
              '(:broker-result :status :open :code 200))
       "broker opens a provider stream with status only")
      (test-assert
       (equal (second frames)
              (list ':broker-chunk ':text (format nil "data: first~%~%")))
       "broker forwards provider text in bounded chunks")
      (test-assert (equal (third frames) '(:broker-end))
                   "broker terminates a complete provider stream")
      (test-assert
       (some (lambda (header)
               (search "broker-secret-token" (rest header)))
             captured-headers)
       "only the trusted provider transport receives the credential")
      (test-assert
       (not (search "broker-secret-token"
                    (with-output-to-string (stream)
                      (prin1 frames stream))))
       "broker response frames never contain the credential")
      (test-assert
       (handler-case
           (progn
             (broker-provider-stream
              configuration "chatgpt"
              (json-encode
               (json-object "model" model
                            "conversation_id" "broker-test-2"
                            "prompt_cache_key" nil
                            "turn_state" nil
                            "force_refresh" *json-decoded-false*
                            "request" (json-object "model" model)
                            "endpoint" "https://attacker.invalid"))
              (lambda (frame) (declare (ignore frame))))
             nil)
         (broker-protocol-error () t))
       "broker rejects an agent-supplied endpoint")))
  nil)

(-> test-broker-trusted-configuration () null)
(defun test-broker-trusted-configuration ()
  "Test the broker uses launcher roots and ignores agent initialization."
  (with-test-configuration (agent root)
    (let ((config-home (merge-pathnames "config/" root))
          (data-home (merge-pathnames "data/" root))
          (state-home (merge-pathnames "state/" root))
          (cache-home (merge-pathnames "cache/" root)))
      (with-test-environment
          (("XDG_CONFIG_HOME" (namestring config-home))
           ("XDG_DATA_HOME" (namestring data-home))
           ("XDG_STATE_HOME" (namestring state-home))
           ("XDG_CACHE_HOME" (namestring cache-home)))
        (let ((broker (broker--configuration)))
          (configuration-ensure-directories broker)
          (test-assert
           (equal (config :config-root broker)
                  (platform-launcher-root *platform* ':config))
           "broker config comes from the launcher root")
          (test-assert
           (not (equal (configuration-user-init-path broker)
                       (configuration-user-init-path agent)))
           "broker initialization is separate from the agent")
          (test-assert
           (null (broker--load-trusted-init broker))
           "broker starts without executing agent initialization")))))
  nil)
