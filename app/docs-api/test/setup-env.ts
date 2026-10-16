// Offline, local-only credentials for moto. Never key-shaped.
process.env.AWS_ACCESS_KEY_ID = "local-only";
process.env.AWS_SECRET_ACCESS_KEY = "local-only";
process.env.AWS_REGION = "us-east-1";
delete process.env.AWS_PROFILE;
