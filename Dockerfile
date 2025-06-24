FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-okta-ciam"]
COPY baton-okta-ciam /