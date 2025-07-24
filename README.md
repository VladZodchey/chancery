# Chancery


Ever wanted a self-hosted text file storage like Pastebin? No? Well, I did.

This piece has these neat features:
- Paste metadata, such as its filetype, author, creation type, additional custom fields.
- User/role system for fine-grained access control
- Read-protected (private) pastes
- ...and more to come!

Contributions are welcome!
I would really appreciate if someone with application security knowledge (and peaceful intent) reviewed the auth thingamabob I made.

> [!WARNING] 
> Please note that this API is still in active pre-release development, things may break, things may change.
> A ton of essential features are not yet implemented.

> [!NOTE]
> You might see GitLab-related config files. Do not worry! This repo is mirrored from a local GitLab instance.

## Running Chancery via Docker
```commandline
docker run vladzodchey/chancery
```

## Building from source
```commandline
git clone https://github.com/VladZodchey/chancery.git ./chancery
cd ./chancery
docker build -t chancery .
docker run chancery
```