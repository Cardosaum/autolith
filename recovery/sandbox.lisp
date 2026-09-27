(in-package #:autolith)

;;;; -- Agent Sandbox --

;;; The pristine recovery image confines every process that runs mutable
;;; Autolith code: the active image the launcher starts, and each generation
;;; or clean source it boots itself. The agent may modify itself, so the
;;; confinement lives here, in the image the agent cannot change, and in the
;;; launcher that asks for it. Commands and Lisp workers the agent starts
;;; inherit the sandbox. It hides the user's home directory, where SSH keys,
;;; cloud tokens, and other logins live, and keeps the launcher, the recovery
;;; image, and the installed runtimes read-only, so a modified agent cannot
;;; replace what starts it next time.

(defparameter *agent-sandbox-variable* "AUTOLITH_AGENT_SANDBOX"
  "The environment variable recording the agent sandbox state: \"active\"
inside the sandbox, so nested launches are not wrapped again, or \"off\" when
the user runs Autolith unconfined.")

(defparameter *agent-sandbox-home-read-paths*
  '("quicklisp/" "common-lisp/")
  "Lisp dependency stores below the home directory that the agent reads.")

(defparameter *agent-sandbox-passthrough-variables*
  '("HOME" "USER" "LOGNAME" "SHELL" "PATH"
    "TERM" "COLORTERM" "LANG" "LC_ALL" "LC_CTYPE"
    "XDG_CONFIG_HOME" "XDG_DATA_HOME" "XDG_STATE_HOME"
    "SBCL_HOME" "AUTOLITH_SBCL" "AUTOLITH_SBCL_SOURCE_ROOT"
    "AUTOLITH_SOURCE_ROOT" "AUTOLITH_PROJECT_SETUP"
    "AUTOLITH_BROKER_SOCKET" "AUTOLITH_BROKER_CAPABILITY"
    "AUTOLITH_CRASH_POINTER"
    "AUTOLITH_RECOVERY_SESSION_POINTER" "AUTOLITH_RESTART_POINTER"
    "AUTOLITH_RECOVERED" "AUTOLITH_RECOVERY_CONVERSATION_ID"
    "AUTOLITH_RECOVERY_HISTORY_FLOOR_SEQUENCE"
    "AUTOLITH_RECOVERY_RENDERED_SEQUENCE"
    "AUTOLITH_SESSION_STYLE" "AUTOLITH_INSTALLATION_KIND"
    "AUTOLITH_RELEASE_ROOT" "AUTOLITH_NIX_SOURCE_ROOT"
    "AUTOLITH_NO_UPDATE_CHECK" "AUTOLITH_SUPPRESS_UPDATE_OFFER"
    "AUTOLITH_MODEL" "AUTOLITH_REASONING_EFFORT"
    "AUTOLITH_WEB_SEARCH" "AUTOLITH_CODEX_FAST_MODE"
    "SSL_CERT_FILE" "NIX_SSL_CERT_FILE")
  "Non-secret launcher environment values passed into the mutable agent.")


;;;; -- Public Functions --

(serapeum:-> agent-sandbox-state () (member :enabled :active :off))
(defun agent-sandbox-state ()
  "Return :ACTIVE inside the agent sandbox, :OFF when the user disabled it, and
:ENABLED when a process launched now must be confined."
  (let ((value (uiop:getenv *agent-sandbox-variable*)))
    (cond
      ((equal value "active")
       ':active)
      ((equal value "off")
       ':off)
      (t
       ':enabled))))

(serapeum:-> agent-sandbox-policy
    (&key (:source-root pathname) (:workspace pathname))
    cl-exec-sandbox:sandbox-policy)
(defun agent-sandbox-policy (&key source-root workspace)
  "Return the sandbox policy for an agent working in WORKSPACE with the tracked
source at SOURCE-ROOT.

The agent may write its workspace, Autolith's own configuration, data, state,
and cache roots, and temporary directories. The source root is read-only even
when it is the workspace, and the images and runtimes the launcher starts
are always read-only, and the rest of the home directory is hidden. The
network stays open. Linux uses a separate process namespace so the agent
cannot inspect the broker through the host process table."
  (let* ((home (uiop:ensure-directory-pathname (user-homedir-pathname)))
         (workspace (uiop:ensure-directory-pathname workspace))
         (launcher-data-root (autolith-launcher-root :data)))
    (when (uiop:subpathp home workspace)
      (error 'agent-sandbox-unavailable
             :message (format nil "Autolith works in ~A, which contains the home directory ~
                                   it would hide. Start it in a project directory, or set ~
                                   ~A=off to run it without the sandbox."
                              (uiop:native-namestring workspace)
                              *agent-sandbox-variable*)))
    (flet ((rule (path access)
             (cl-exec-sandbox:make-filesystem-rule :kind ':path :path path :access access))
           (special (path access)
             (cl-exec-sandbox:make-filesystem-rule :kind ':special :path path :access access)))
      (cl-exec-sandbox:make-sandbox-policy
       :network ':enabled
       :unix-socket-paths
       (when (uiop:getenv "AUTOLITH_BROKER_SOCKET")
         (list (pathname (uiop:getenv "AUTOLITH_BROKER_SOCKET"))))
       :private-tmp-p t
       :private-runtime-p t
       :isolate-processes-p t
       :workspace-roots
       (unless (uiop:subpathp workspace source-root)
         (list workspace))
       :protected-metadata-names nil
       :filesystem-rules
       (append
        (list (special ':root ':read)
              (special ':home ':deny)
              (special ':search-path ':read)
              (special ':workspace-roots ':write)
              (special ':slash-tmp ':write))
        (mapcar (lambda (kind) (rule (autolith-application-root kind) ':write))
                '(:config :data :state :cache))
        (list (rule launcher-data-root ':read))
        (when (uiop:getenv "AUTOLITH_BROKER_SOCKET")
          (list (rule (agent-sandbox--broker-directory) ':read)))
        (when (uiop:getenv "AUTOLITH_LAUNCHER_TERMINAL")
          (list (rule (agent-sandbox--launcher-terminal) ':deny)))
        (mapcar (lambda (kind) (rule (autolith-launcher-root kind) ':deny))
                '(:config :state :cache))
        (list (rule source-root ':read))
        (loop for relative in *agent-sandbox-home-read-paths*
              for path = (merge-pathnames relative home)
              when (probe-file path)
                collect (rule path ':read))
        (agent-sandbox--runtime-rules))))))

(serapeum:-> agent-sandbox-wrap
    (list &key (:source-root pathname) (:workspace pathname)
               (:working-directory pathname))
    list)
(defun agent-sandbox-wrap (command &key source-root workspace (working-directory workspace))
  "Return the argument vector that runs COMMAND, a program and its arguments,
inside the agent sandbox for WORKSPACE and SOURCE-ROOT, starting in
WORKING-DIRECTORY, which defaults to WORKSPACE.

COMMAND is returned unchanged inside the sandbox, when the user disabled it,
and on Windows, whose launcher does not confine the agent yet. Signal
AGENT-SANDBOX-UNAVAILABLE when this host has no sandbox backend."
  (if (or (not (eq (agent-sandbox-state) ':enabled))
          (uiop:os-windows-p))
      command
      (let* ((inner (agent-sandbox--with-environment command))
             (plan (handler-case
                       (cl-exec-sandbox:sandbox-build-plan
                        (first inner) (rest inner)
                        :policy (agent-sandbox-policy :source-root source-root
                                                      :workspace workspace)
                        :working-directory working-directory)
                     (cl-exec-sandbox:sandbox-unavailable (condition)
                       (error 'agent-sandbox-unavailable
                              :message (format nil "~A Set ~A=off to run Autolith without ~
                                                    the sandbox."
                                               condition *agent-sandbox-variable*))))))
        (when (cl-exec-sandbox:sandbox-plan-cleanup-paths plan)
          (error 'agent-sandbox-unavailable
                 :message "The agent sandbox would need files the launcher cannot remove."))
        (cons (uiop:native-namestring (cl-exec-sandbox:sandbox-plan-program plan))
              (cl-exec-sandbox:sandbox-plan-arguments plan)))))

(serapeum:-> agent-sandbox-cache-home () pathname)
(defun agent-sandbox-cache-home ()
  "Return the XDG cache home of processes inside the agent sandbox.

The user's own caches are hidden, because unconfined programs, recovery among
them, load compiled files from the ASDF cache there: a file the agent compiled
into it could run outside the sandbox. Inside, ASDF's default cache and
Autolith's cache root both follow this directory, below Autolith's own cache,
whatever output translations the runtime installs."
  (merge-pathnames "agent-sandbox/" (autolith-application-root :cache)))

(serapeum:-> agent-sandbox-print-command (pathname list) integer)
(defun agent-sandbox-print-command (source-root command)
  "Write the sandboxed argument vector for COMMAND to standard output, each
argument followed by a NUL character, for the launcher to run. Return the
process status: 0, or 1 after explaining why the sandbox is unavailable."
  (handler-case
      (let ((wrapped (agent-sandbox-wrap command
                                         :source-root source-root
                                         :workspace (uiop:getcwd))))
        (dolist (argument wrapped)
          (write-string argument)
          (write-char (code-char 0)))
        (finish-output)
        0)
    (agent-sandbox-unavailable (condition)
      (format *error-output* "Autolith cannot start its sandbox: ~A~%" condition)
      1)))


;;;; -- Private Functions --

(serapeum:-> agent-sandbox--launcher-terminal () pathname)
(defun agent-sandbox--launcher-terminal ()
  "Validate the real launcher terminal that the agent must never open."
  (let ((value (uiop:getenv "AUTOLITH_LAUNCHER_TERMINAL")))
    (unless (and value
                 (uiop:absolute-pathname-p (pathname value))
                 (uiop:subpathp (pathname value) #P"/dev/")
                 (probe-file value))
      (error 'agent-sandbox-unavailable
             :message "The launcher terminal path is invalid."))
    (pathname value)))

(serapeum:-> agent-sandbox--broker-directory () pathname)
(defun agent-sandbox--broker-directory ()
  "Return the private launcher-created runtime directory for the broker socket."
  (let* ((value (uiop:getenv "AUTOLITH_BROKER_SOCKET"))
         (socket (and value (pathname value)))
         (directory (and socket
                         (uiop:pathname-directory-pathname socket)))
         (component (and directory
                         (first (last (pathname-directory directory)))))
         (broker-root (merge-pathnames
                       "broker/" (autolith-launcher-root :state))))
    (unless (and socket
                 (uiop:subpathp socket broker-root)
                 (string= (file-namestring socket) "broker.sock")
                 (stringp component)
                 (<= (length "session.") (length component))
                 (string= component "session."
                          :end1 (length "session.")))
      (error 'agent-sandbox-unavailable
             :message "The credential broker socket directory is invalid."))
    directory))

(serapeum:-> agent-sandbox--with-environment (list) list)
(defun agent-sandbox--with-environment (command)
  "Return COMMAND with a small environment and its cache inside the sandbox.

A Nix installation compiles Autolith's source into AUTOLITH_ASDF_CACHE, which
its unconfined image builder also loads, so the agent gets its own there too.
Credential-bearing and unrecognized host variables never enter the agent."
  (let* ((cache-home (agent-sandbox-cache-home))
         (nix-cache (uiop:getenv "AUTOLITH_ASDF_CACHE"))
         (nix-identity (and nix-cache
                            (plusp (length nix-cache))
                            (first (last (pathname-directory
                                          (uiop:ensure-directory-pathname nix-cache))))))
         (bindings
           (loop for name in *agent-sandbox-passthrough-variables*
                 for value = (uiop:getenv name)
                 when value
                   collect (format nil "~A=~A" name value))))
    (setf bindings
          (append bindings
                  (list
                   (format nil "XDG_CACHE_HOME=~A"
                           (string-right-trim "/"
                                              (uiop:native-namestring cache-home)))
                   "TMPDIR=/tmp"
                   "AUTOLITH_AGENT_SANDBOX=active")))
    (when nix-identity
      (setf bindings
            (append bindings
                    (list (format nil "AUTOLITH_ASDF_CACHE=~A"
                                  (uiop:native-namestring
                                   (merge-pathnames (format nil "nix-asdf/~A/" nix-identity)
                                                    cache-home)))))))
    (append (list "/usr/bin/env" "-i") bindings command)))

(serapeum:-> agent-sandbox--runtime-rules () list)
(defun agent-sandbox--runtime-rules ()
  "Return read rules for the SBCL runtime and dependency setup the environment
names, which may live below the hidden home directory."
  (loop for (variable . directory-p) in '(("AUTOLITH_SBCL" . nil)
                                          ("SBCL_HOME" . t)
                                          ("AUTOLITH_PROJECT_SETUP" . nil))
        for value = (uiop:getenv variable)
        for path = (and value
                        (uiop:absolute-pathname-p (pathname value))
                        (if directory-p
                            (uiop:ensure-directory-pathname value)
                            (uiop:pathname-directory-pathname value)))
        when (and path (probe-file path))
          collect (cl-exec-sandbox:make-filesystem-rule :kind ':path
                                                        :path path
                                                        :access ':read)))


;;;; -- Conditions --

(define-condition agent-sandbox-unavailable (error)
  ((message
    :initarg :message
    :reader agent-sandbox-unavailable-message
    :documentation "Why the agent cannot be started inside its sandbox."))
  (:documentation "Signaled when the agent sandbox cannot confine a launch.")
  (:report (lambda (condition stream)
             (write-string (agent-sandbox-unavailable-message condition) stream))))
