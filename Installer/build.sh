set -e

# Name of the package.
NAME="WizardInstaller.pkg"

# Once installed the identifier is used as the filename for a receipt files in /var/db/receipts/.
IDENTIFIER="com.santalvarez.wizard.pkg"

INSTALL_LOCATION="/"

/usr/bin/pkgbuild --analyze --root Files wizard-component.plist

/usr/bin/plutil -replace BundleIsRelocatable -bool NO wizard-component.plist

/usr/bin/pkgbuild \
    --root Files/ \
    --sign "$CERT" \
    --scripts Scripts/ \
    --install-location "$INSTALL_LOCATION" \
    --identifier "$IDENTIFIER" \
    --component-plist wizard-component.plist \
    --version "$VERSION" \
    "$NAME"

/usr/sbin/pkgutil --check-signature ${NAME} || die "bad pkg signature"

xcrun notarytool submit $NAME --wait --keychain-profile "wizard-notary-profile"

xcrun stapler staple $NAME

