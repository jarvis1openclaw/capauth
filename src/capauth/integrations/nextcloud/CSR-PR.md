# Certificate-request PR — ready to submit

Submit this to <https://github.com/nextcloud/app-certificate-requests>.
**Requires Chef's GitHub account (with a public email set on the profile).**

## File to create in the PR

Path (in the `app-certificate-requests` repo): **`capauth/capauth.csr`**

Contents (paste exactly — this is `certificates/capauth.csr`):

```
-----BEGIN CERTIFICATE REQUEST-----
MIIEVzCCAj8CAQAwEjEQMA4GA1UEAwwHY2FwYXV0aDCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAN0TfQd2PyYMpU5YKiyEdJqNHaGCf7mucblYIZtCYQCu
kv2vZKJRdbnne2br4S7FNNnbDez9Jp2yQNCnkooKkC+g7RIsTaR7syrIMD8HCpwa
//fqWiPaY/RlqHFNUGwJx9o6tjY1uwQ5cPbFFof7jNidEAAwaLPrjsua3wPzGZLs
pvg5Es+mQ7ZqTicHWxqBx/5G6jI5YE4lKwFRO+I9dpfWvi8Cct5MpoAq7bA88A6d
YDP+GCATmRr+mXJ7STDa+VcN1+w//2PKHJlVj/ssjWzWE2zt4z1jWUFjuj9E80fL
zruwv13dRudNBpKvkiP5kWEBy4zrFavTEHjaSjZ1l4xkY6tj9Xtv921wF0f+6x7b
tTk62ITRtZ1rlHuOGIEEt6OtiyYp/jIo7Hk+FWjb7+sGcJ5wM1z7ZGFavEdmWRsv
uj2MMqpMKtyjdEMrhSj6uwILSddPk9JlSEsuKpua0LQgjYEoU4DkRkJgi/Q4f90/
Z7kiBWbW3mPpy8N1SMhgRq8wzXqChnNqYWH7A7NejhTfEH8leMo0YJVEYMnirnuU
Te1JcvTQDsUf2kwRpP3iCifpNyifr5Ey6x3oYU4cookaXqewR9AbVKT731hWPMCE
OdW0y2jjModd9dLUKKVL33CbKse0Lklh9sz02/WiMVS3E+IX6nYSke2ts2/uC+IF
AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAgEAJLDLT9XQEf8i4jwi9vNuqATTz5wJ
2XFRrB5zhdxMiBNOvy3VeWKJzltgTgB8Lhr9UQBzzYnz63ExtHMZZLcwBVKew02l
bpxxfYjpHdeA/u0yFFQQTt2plXP+PvUZ0GbFL4Inia7FX4A3BONvwtLlMrR2G3hw
+GI3DCTQBusi9ITusx+rNaUepgb+v5bEfbTTRu8nAEZyqLQXA5rgUeFdsi1/7jgn
Dr6GvWBjQxRMVbMe+MfWReb8zZfCbqeSbqScjYbqUDn52zVlAj3jBLrQccB16x1W
J88gBiiOzAafRtgnM5U1FxCiGlVxh/pYKpU1BMGQwAW48dApjjBgmbeYd70sDZS1
365CMFTpC293U2ozDFxHeJ6lVa8si+d3dD5pH/jecNLJ0VOI7ffYHKdUcYBea8fp
q2R8mR95kNlWYqz1b2TAHThSrXfST4/QIGiN6s665BqdTEyUyHlZ4bZBugP95jRJ
XMWLJOH3VlqpfgPQDZoaOz/1fN4e0NHCVa+TKnhMOcCj032c/Vqoabi6AUlONPgH
KAV6QIVoKnHPF/d4UHjNpAC7WWzJVoGWxPDx/Uln16IOPS5oWQIcnYCUQ5w3mk+z
LHHssMoQ/fAkMOKYCvYim5i1oK81RVqJ9Ybbi/aR0WBn1NowSAjJ4FYteQkPanQ7
DfriWGfrvF+Rl9s=
-----END CERTIFICATE REQUEST-----
```

> The CSR's Common Name is `CN=capauth` — verified to equal the app id, which
> is the hard requirement. Do **not** also add the `.crt`; Nextcloud creates it.

## PR title

```
Add certificate for capauth
```

## PR body

```
Certificate request for the CapAuth app (app id: capauth).

Passwordless PGP primary-login user backend for Nextcloud.
Source: https://github.com/smilintux/capauth
```

## After merge

Nextcloud issues `capauth.crt`. Save it to **both**:
- `~/.nextcloud/certificates/capauth.crt` (for krankerl / local signing), and
- `certificates/capauth.crt` in this repo (commit it — the .crt is public).

See `PUBLISHING.md` steps 1c–1d.
