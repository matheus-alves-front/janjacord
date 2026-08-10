/**
 * Config plugin do Expo — injeta o módulo nativo JanjacordCrypto no projeto Android
 * durante o prebuild (expo prebuild / run:android / eas build).
 */
const { withAndroid, AndroidConfig } = require("@expo/config-plugins");

module.exports = function withJanjacordCrypto(config) {
  return withAndroid(config, (config) => {
    const projectRoot = config.modRequest.projectRoot;

    // 1. registra o módulo no settings.gradle
    const settingsGradle = AndroidConfig.Paths.getSettingsGradlePath(projectRoot);
    const fs = require("fs");
    let settings = fs.readFileSync(settingsGradle, "utf8");
    if (!settings.includes("janjacord-crypto")) {
      settings += `\ninclude ':janjacord-crypto'\nproject(':janjacord-crypto').projectDir = new File(rootProject.projectDir, '../modules/janjacord-crypto/android')\n`;
      fs.writeFileSync(settingsGradle, settings);
    }

    // 2. inclui o módulo como dependência do app
    const appBuildGradle = AndroidConfig.Paths.getAppBuildGradlePath(projectRoot);
    let appGradle = fs.readFileSync(appBuildGradle, "utf8");
    if (!appGradle.includes("janjacord-crypto")) {
      appGradle = appGradle.replace(
        /dependencies\s*\{/,
        "dependencies {\n    implementation project(':janjacord-crypto')"
      );
      fs.writeFileSync(appBuildGradle, appGradle);
    }

    // 3. registra o ReactPackage (compatível com New Arch via interop)
    const mainApplication = AndroidConfig.Paths.getMainApplicationPath(projectRoot);
    let mainApp = fs.readFileSync(mainApplication, "utf8");
    if (!mainApp.includes("JanjacordCryptoPackage")) {
      mainApp = mainApp.replace(
        "new MainReactPackage()",
        "new MainReactPackage(), new br.janjacord.crypto.JanjacordCryptoPackage()"
      );
      fs.writeFileSync(mainApplication, mainApp);
    }
    return config;
  });
};
