# GeoLite2 Database

This folder should contain the GeoLite2-City.mmdb database file.

## Download Instructions

1. Sign up for a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Log in to your MaxMind account
3. Go to "Download Files"
4. Download "GeoLite2 City" in MMDB format
5. Extract the downloaded file
6. Copy `GeoLite2-City.mmdb` to this folder (`backend/data/`)

## File Required
- `GeoLite2-City.mmdb`

The geolocation feature will not work without this database file.

## Note
The database file is large (~50-100MB) and is not included in the repository.
You must download it separately from MaxMind.
