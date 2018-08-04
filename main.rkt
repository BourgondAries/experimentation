#! /usr/bin/env racket
#lang racket

(require
  anaphoric
  libuuid
  sha
  syntax/parse/define
  web-server/dispatch
  web-server/servlet
  web-server/servlet-env
  )

;; How do we keep login credentials updated?
(define login-credentials
  (hash "kefin"
        (hash 'pwhash "6c26a6c7b7c36bc4a5fb123f9cfcb3bb0b7f69d9a3d81ae2280672b25e52dfc7d1440a0f2ddf90d885d51236fab22c478b21afab30c4205e20f818b79be2089d"
              'token "kkkkkkkkasd")))

(define (get-cookie req name)
  (let ([result (findf (lambda (x) (string=? name (client-cookie-name x)))
                       (request-cookies req))])
    (if result
      (client-cookie-value result)
      result)))

(define (mapone f v) (if v (f v) v))

(define (get-post req name)
  (mapone cdr (findf (lambda (x) (symbol=? name (car x))) (request-bindings req))))

(define (login-page req)
  (response/xexpr
    '(html (head (title "Login"))
           (body (form ([method "post"])
                       (input ([name "login:username"]  [placeholder "username"]     [type "text"]))
                       (input ([name "login:passcode"]  [placeholder "passcode"]     [type "password"]))
                       (input ([name "login:passcode*"] [placeholder "new passcode"] [type "password"]))
                       (input ([type "submit"])))
                 (p "There is no passcode strength requirement but we suggest to use a password manager and ensure passcode entropy is higher than 80 bits (> 18 characters).")
                 (p "Leave 'new passcode' empty if you do not wish to renew your passcode.")
                 (p "Contact your supervisor if you have lost your password.")))))

(define-values (dispatch url)
  (dispatch-rules
    [else (lambda _ (response/xexpr '(html (body "nice"))))]))

(define (is-logged-in? req)
  (let* ([user  (get-cookie req "user")]
         [token (get-cookie req "token")])
    (writeln `("login cookie" ,user))
    (writeln `("login cookie" ,token))
    (if user
      (let ([user* (hash-ref login-credentials user #f)])
        (if token
          (let ([l (equal? (hash-ref user* 'token #f) token)])
            (writeln `(nolg ,user*))
            (writeln `(notloggedin2 ,l))
            l)
          #f))
      (begin
        (writeln `(notloggedin #f))
        #f))))

(define (login-request? req)
  (writeln `(login-request? ,(and (get-post req 'login:username) (get-post req 'login:passcode))))
  (and (get-post req 'login:username) (get-post req 'login:passcode)))

(define (get-pw-hash user)
  (define user* (hash-ref login-credentials user #f))
  (if user*
    (hash-ref user* 'pwhash #f)
    #f))

(define (get-token user)
  (define user* (hash-ref login-credentials user #f))
  (if user*
    (hash-ref user* 'token #f)
    #f))

(define (attempt-login req)
  (define username (get-post req 'login:username))
  (define passcode (get-post req 'login:passcode))
  (if (equal?
        (bytes->hex-string (sha512 (string->bytes/utf-8 passcode)))
        (get-pw-hash username))
    (redirect-to
      (url->string (request-uri req))
      #:headers (list (cookie->header (make-cookie "user" username))
                      (cookie->header (make-cookie "token" (get-token username)))))
    (redirect-to
      (url->string (request-uri req)))
    ))

;; Handle all requests by checking if the user is logged in.
;; otherwise return a login page.
(define (gatekeeper req)
  (cond
    ([is-logged-in?  req] (dispatch req))
    ([login-request? req] (attempt-login req))
    (else                 (login-page req))
  ))

(serve/servlet gatekeeper
               #:port 8000
               #:servlet-regexp #rx"")
