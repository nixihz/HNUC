
package:
	fyne package -os darwin -icon assets/logo.png
	codesign --force --deep --sign - hnuc.app
	zip -r hnuc.zip hnuc.app

clean:
	rm -rf hnuc.zip hnuc.log hnuc.app/
