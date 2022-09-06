# Request/Response Signature

Before you proceed, please read the public documentation for the [request signature process](https://developers.pomelo.la/en/api-reference/cards/transactions#cards-transactions-request-signature-process).

In order to validate requests are coming from a trusted source, Pomelo signs each request using the [HMAC-SHA algorithm](https://en.wikipedia.org/wiki/HMAC).
This doesn't require any session management nor a third party, only a shared key and secret between you and Pomelo. 
This key will be given to you during the onboarding process.

This directory contains example code on how to validate each incoming request to your backend, as well as
code to sign each response. This is meant to be used as a reference (for copy-pasting into your codebase) or
as a full implementation if you so desire. Keep in mind we don't offer SDKs or libraries at the moment, so
you'll need to copy and adapt the code to suit your needs. The algorithm itself is production ready tough, both in terms
of security and performance.

For example purposes, these examples contain a hardcoded `api-key` and `api-secret`, but for production usage
you'll need to set up the credentials given to you by the integration team during the onboarding. We recommend storing
them somewhere safe, and not hardcoding them in the source code directly.

## Directory structure

Each folder contains a runnable sample http server that implements signature validation + generation in a different language.

The README file inside each directory contains instructions on how to run each example and how to test it yourself.

You can test each server implementation with our included postman collection.