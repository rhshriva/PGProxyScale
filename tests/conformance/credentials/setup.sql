DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pgproxy_credential_a') THEN CREATE ROLE pgproxy_credential_a LOGIN PASSWORD 'pgproxy-credential-test-a'; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pgproxy_credential_b') THEN CREATE ROLE pgproxy_credential_b LOGIN PASSWORD 'pgproxy-credential-test-b'; END IF;
END $$;
GRANT CONNECT ON DATABASE conformance TO pgproxy_credential_a, pgproxy_credential_b;
