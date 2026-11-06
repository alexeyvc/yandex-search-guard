import os, secrets
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write('ADMIN_USER=admin\nADMIN_PASSWORD=' + secrets.token_urlsafe(32) + '\nSEARCH_TOKEN=' + secrets.token_urlsafe(32) + '\n')
    f.write("GUARD_USERS_JSON='{}'\nSESSION_HOURS=8\nSESSION_COOKIE_SECURE=true\n")
print('Created .env; existing files are never overwritten. Keep credentials private.')
