# Building Wizard

Wizard uses `bazel` to build and run the tests.

To build Wizard, run the following command:
```bash
bazel build //Sources/wizard:wizard --define=WIZARD_BUILD=dev
```


To run the tests, run the following command:
```bash
bazel test :tests --test_output=errors
```

We normally use Xcode as our IDE so here is how you can generate the xcodeproj files:
```bash
bazel run //Sources/wizard:xcodeproj --define=WIZARD_BUILD=dev
```

