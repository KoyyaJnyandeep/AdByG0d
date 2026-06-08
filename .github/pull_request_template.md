## Summary

- 

## Verification

- [ ] `python -m compileall -q apps/api/src collectors/linux_remote/src`
- [ ] `python -m ruff check apps/api/src collectors/linux_remote/src apps/api/tests`
- [ ] `python -m pytest apps/api/tests -q`
- [ ] `npm --prefix apps/web run lint`
- [ ] `npm --prefix apps/web run type-check -- --pretty false`
- [ ] `npm --prefix apps/web run build`

## Security Checklist

- [ ] No secrets, tokens, passwords, private keys, hashes, tickets, local databases, logs, screenshots, reports, or real engagement evidence are included.
- [ ] Dangerous features remain disabled by default.
- [ ] Authorization and production safety checks are not weakened.
- [ ] New environment variables are documented in examples and docs.

## Notes

Use synthetic fixtures for tests and examples.
