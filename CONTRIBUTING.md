# Contributing to Gyrai

Thanks for your interest. Gyrai is early, so small, focused changes are easiest to review.

## Before you start

- Open an issue to discuss larger changes first.
- Never commit secrets, real tenant identifiers or customer data. `.env` files are ignored by git; keep it that way.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
opa test policies/        # if OPA is installed
```

CI runs the same checks. Pull requests need passing tests and a clean `ruff check`.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/). Add a sign-off line to each commit:

```bash
git commit -s -m "Describe the change"
```

By signing off you confirm that you wrote the change or have the right to submit it under the project's license.

## License

By contributing you agree that your contributions are licensed under the Apache License 2.0, the same as the project.
