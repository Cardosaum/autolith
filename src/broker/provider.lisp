(in-package #:autolith)

;;;; -- Trusted Provider Transport --

(defparameter *broker-provider-chunk-size* 4096
  "The maximum number of provider characters in one broker response chunk.")

(-> broker-provider--bounded-header-value-p (t) boolean)
(defun broker-provider--bounded-header-value-p (value)
  "Return true for a small header value without control characters."
  (and (stringp value)
       (<= (length value) 256)
       (every (lambda (character)
                (<= 32 (char-code character) 126))
              value)
       t))

(-> broker-provider--payload (string) json-object)
(defun broker-provider--payload (source)
  "Decode an exact provider request without granting endpoint authority."
  (let ((value (handler-case (json-decode source)
                 (error () nil))))
    (unless (and (json-object-p value)
                 (= (hash-table-count value) 6)
                 (every (lambda (key)
                          (nth-value 1 (gethash key value)))
                        '("model" "conversation_id" "prompt_cache_key"
                          "turn_state" "force_refresh" "request"))
                 (non-empty-string-p (json-get value "model"))
                 (<= (length (json-get value "model")) 128)
                 (non-empty-string-p (json-get value "conversation_id"))
                 (broker-provider--bounded-header-value-p
                  (json-get value "conversation_id"))
                 (or (null (json-get value "prompt_cache_key"))
                     (broker-provider--bounded-header-value-p
                      (json-get value "prompt_cache_key")))
                 (or (null (json-get value "turn_state"))
                     (broker-provider--bounded-header-value-p
                      (json-get value "turn_state")))
                 (member (gethash "force_refresh" value)
                         (list t *json-decoded-false*))
                 (json-object-p (json-get value "request"))
                 (json-string= (json-get (json-get value "request") "model")
                               (json-get value "model")))
      (error 'broker-protocol-error
             :message "The broker provider payload is invalid."
             :reason ':payload))
    value))

(-> broker-provider--resolve
    (configuration string json-object)
    (values model-provider conversation boolean))
(defun broker-provider--resolve (configuration target payload)
  "Select a trusted provider and a detached conversation from its registry."
  (let* ((model (json-get payload "model"))
         (registration (provider-registration-find target)))
    (unless (and registration
                 (some (lambda (candidate)
                         (string= (provider-model-name candidate) model))
                       (provider-registration-models registration)))
      (error 'broker-protocol-error
             :message "The requested provider or model is not registered."
             :reason ':target))
    (let* ((request-configuration
             (configuration-copy configuration :model model))
           (provider
             (provider-create request-configuration
                              :registration registration))
           (conversation
             (conversation-create
              request-configuration
              :identifier (json-get payload "conversation_id")
              :prompt-cache-key (json-get payload "prompt_cache_key"))))
      (setf (conversation-turn-state conversation)
            (json-get payload "turn_state"))
      (values provider conversation
              (eq (gethash "force_refresh" payload) t)))))

(-> broker-provider--copy-stream (stream function) null)
(defun broker-provider--copy-stream (stream write-frame)
  "Forward one provider character stream as bounded broker chunks."
  (let ((buffer (make-string *broker-provider-chunk-size*)))
    (loop
      for count = (read-sequence buffer stream)
      while (plusp count)
      do (funcall write-frame
                  (list ':broker-chunk ':text (subseq buffer 0 count)))))
  (funcall write-frame '(:broker-end))
  nil)

(-> broker-provider-stream
    (configuration string string function)
    null)
(defun broker-provider-stream (configuration target source write-frame)
  "Run a provider request with broker-owned credentials and stream its body."
  (let ((payload (broker-provider--payload source)))
    (multiple-value-bind (provider conversation force-refresh)
        (broker-provider--resolve configuration target payload)
      (call-with-credentials
       (provider-credential-manager provider)
       (lambda (credentials)
         (multiple-value-bind (body status headers)
             (provider-open-response-stream
              provider (json-get payload "request")
              :credentials credentials :conversation conversation)
           (declare (ignore headers))
           (unwind-protect
                (progn
                  (funcall write-frame
                           (list ':broker-result ':status ':open ':code status))
                  (broker-provider--copy-stream body write-frame))
             (close body))))
       :force-refresh force-refresh)))
  nil)

(-> broker-provider-compact
    (configuration string string function)
    null)
(defun broker-provider-compact (configuration target source write-frame)
  "Run Codex native compaction using only the broker's credentials."
  (let ((payload (broker-provider--payload source)))
    (multiple-value-bind (provider conversation force-refresh)
        (broker-provider--resolve configuration target payload)
      (unless (typep provider 'codex-subscription-provider)
        (error 'broker-protocol-error
               :message "Native compaction is unavailable for this provider."
               :reason ':target))
      (call-with-credentials
       (provider-credential-manager provider)
       (lambda (credentials)
         (multiple-value-bind (body status headers)
             (provider-open-native-compaction
              provider (json-get payload "request")
              :credentials credentials :conversation conversation)
           (declare (ignore headers))
           (funcall write-frame
                    (list ':broker-result ':status ':open ':code status))
           (with-input-from-string (stream body)
             (broker-provider--copy-stream stream write-frame))))
       :force-refresh force-refresh)))
  nil)

(-> broker-provider-discover (configuration string string function) null)
(defun broker-provider-discover (configuration target source write-frame)
  "Discover one trusted registration's models with broker-owned credentials."
  (unless (string= source "")
    (error 'broker-protocol-error
           :message "Model discovery takes no agent payload."
           :reason ':payload))
  (let* ((registration (provider-registration-find target))
         (discovery (and registration
                         (provider-registration-model-discovery registration))))
    (unless discovery
      (error 'broker-protocol-error
             :message "The target has no trusted model discovery."
             :reason ':target))
    (let ((models (provider--normalize-models
                   (funcall discovery configuration) :allow-empty-p t)))
      (when (> (length models) 1024)
        (error 'broker-protocol-error
               :message "The discovered model list is too large."
               :reason ':response))
      (funcall write-frame
               (list ':broker-result ':status ':models
                     ':models (mapcar #'provider--model-cache-form models)))))
  nil)
