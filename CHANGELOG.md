# Changelog

## Version 2.0.5

2024-11-03

- Fix extraneous newline being printed on windows

## Version 2.0.4

2024-10-27

- Various windows fixes. Add check for null stdin handle, and avoid closing it
- Upgrade zeroize version

## Version 2.0.3

2023-12-15

- Remove usage of windows-sys

## Version 2.0.2

2023-12-15

- Upgrade dependencies

## Version 2.0.1

2023-07-27

- Fix for zeroize on unix targets

## Version 2.0.0

2023-07-20

- Rename password functions
- Add ability to read a password from the tty

## Version 1.1.7

- Fix for windows create update
- Bump windows crate version to >=0.44

## Version 1.1.6
- Update documentation

## Version 1.1.5
- Remove panic on handle acquisition failure on windows

## Version 1.1.4
- Fix for windows crate update
- Bump windows crate version to >=0.37

## Version 1.1.3
- Fix broken console mode from windows crate update

## Version 1.1.2
- Relax windows crate dependency version

## Version 1.1.1
- Upgrade windows dep

## Version 1.1.0
- Add isatty function.

## Version 1.0.3
- Fix Cargo.toml license line

## Version 1.0.2
- Fix handling of input that has been piped. Echo is now disabled only
  when a terminal is present.

## Version 1.0.1
- Update documentation

## Version 1.0.0
- Initial Release
- Read a password from the console.
