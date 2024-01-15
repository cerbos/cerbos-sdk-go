Contributing to Cerbos Go SDK
=============================

Thank you for your interest in Cerbos. We welcome contributions from the community. Please note that we have a [code of conduct](https://github.com/cerbos/.github/blob/main/CODE_OF_CONDUCT.md) that must be followed when interacting with this project. In addition, please read the guidelines below to ensure that your contributions have a better chance of being accepted.

- [Submitting pull requests](#submitting-pull-requests)
    - [Code changes](#submitting-pull-requests-for-code-changes)
- [Developing Cerbos Go SDK](#developing-cerbos-go-sdk)

Submitting pull requests
------------------------

- Before submitting a pull request, please [raise an issue](https://github.com/cerbos/cerbos-sdk-go/issues) in the GitHub repository and provide information about the problem you are trying to fix and how you plan to address it. Include as much detail as possible to make it easier for others to understand your thought process.
- Wait for the project maintainers and other community members to respond to your proposal and clearly agree on a course of action.
- Create your patch, constraining yourself to what was agreed on the issue. If previously unforeseen problems arise and you have to make significant changes to an area that wasn’t discussed in the issue, make sure to go back to the issue to discuss the new circumstances and get buy-in from the people who are involved.
- Run the pre-commit checks that are appropriate for the kind of change. (See below for details.)
- Submit your pull request.
    - We require all pull requests to follow the [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) format.
    - Use [closing keywords](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) to link the PR to the original issue.
    - At least one approval from a maintainer is required to merge the pull request.


### Submitting pull requests for code changes

- Write idiomatic Go. [Effective Go](https://golang.org/doc/effective_go) is the canonical source while the [Uber style guide](https://github.com/uber-go/guide/blob/master/style.md) contains a lot of good advice as well.
- Make sure each source file contains the appropriate licence header:
    ```
    Copyright 2021-2024 Zenauth Ltd.
    SPDX-License-Identifier: Apache-2.0
    ```
- Add tests to cover the functionality you are adding or modifying.
- Add new documentation or update existing content to ensure that the documentation stays consistent with the change you are introducing.
- Avoid introducing new dependencies if possible. All dependencies must have an appropriate open source licence (Apache-2.0, BSD, MIT).
- Make sure your code is `gofmt`ed. Run `just lint` and fix any warnings produced by the linter.
- Sign-off your commits to provide a [DCO](https://developercertificate.org). You can do this by adding the `-s` flag to your `git commit` command.
    ```sh
    git commit -s -m 'bug: Fix for bug X'
    ```


Developing Cerbos Go SDK
------------------------

We currently require Go 1.20.x for development. [Just](https://just.systems/man/en/chapter_1.html) is used for build tasks. Run `just` at the root of the directory to see the list of available targets.
