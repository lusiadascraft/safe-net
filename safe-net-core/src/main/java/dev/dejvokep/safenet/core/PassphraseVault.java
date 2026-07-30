/*
 * Copyright 2025 https://dejvokep.dev/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.dejvokep.safenet.core;

import dev.dejvokep.boostedyaml.YamlDocument;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * A class covering all needed functions related to passphrase.
 */
public class PassphraseVault {

    /**
     * Default passphrase property name.
     */
    public static final String DEFAULT_PASSPHRASE_PROPERTY_NAME = "safe_net_passphrase";

    /**
     * Recommended passphrase length.
     */
    public static final int RECOMMENDED_PASSPHRASE_LENGTH = 1000;

    /**
     * Passphrases with lengths below this threshold are considered weak and should be reset immediately.
     */
    public static final int WEAK_PASSPHRASE_LENGTH_THRESHOLD = 50;

    /**
     * Immutable credentials snapshot. A reload publishes both values with one volatile write.
     */
    private volatile Credentials credentials;

    // Config
    private final YamlDocument config;
    // Logger
    private final Logger logger;

    /**
     * Loads the internal data.
     *
     * @param config the configuration file
     * @param logger the logger
     */
    public PassphraseVault(@NotNull YamlDocument config, @NotNull Logger logger) {
        this.config = config;
        this.logger = logger;
        reload();
    }

    /**
     * Generates a new passphrase of the specified length and sets it into the configuration file.
     *
     * @param length the desired length of the new passphrase (<code>length > 0</code>)
     */
    public final void generatePassphrase(int length) throws IOException {
        if (length < 1)
            return;

        config.set("passphrase", KeyGenerator.generate(length));
        config.save();
    }

    /**
     * Returns the current status of the passphrase.
     * <ul>
     *     <li><code>length == 0</code>: invalid</li>
     *     <li><code>length < {@link #WEAK_PASSPHRASE_LENGTH_THRESHOLD}</code>: weak</li>
     *     <li><code>length >= {@link #WEAK_PASSPHRASE_LENGTH_THRESHOLD}</code>: valid</li>
     * </ul>
     *
     * @return the passphrase status
     */
    public String getPassphraseStatus() {
        String passphrase = credentials.getPassphrase();
        return passphrase.length() == 0
                ? "invalid"
                : passphrase.length() < WEAK_PASSPHRASE_LENGTH_THRESHOLD ? "weak" : "valid";
    }

    /**
     * Reloads the passphrase components and publishes them atomically.
     */
    public void reload() {
        String loadedPassphrase = config.getString("passphrase", "");
        String loadedPropertyName = config.getString(
                "property-name.handshake",
                DEFAULT_PASSPHRASE_PROPERTY_NAME
        );

        credentials = new Credentials(loadedPassphrase, loadedPropertyName);
        printStatus();
    }

    /**
     * Prints the passphrase status.
     */
    public void printStatus() {
        String passphrase = credentials.getPassphrase();

        if (passphrase.length() == 0)
            logger.severe("No passphrase configured (length is 0)! The plugin will disconnect all incoming connections. Please generate one as soon as possible from the proxy console with \"/sn generate\".");
        else if (passphrase.length() < WEAK_PASSPHRASE_LENGTH_THRESHOLD)
            logger.warning("The configured passphrase is weak! It should be at least " + WEAK_PASSPHRASE_LENGTH_THRESHOLD + " characters long; though the recommended length is " + RECOMMENDED_PASSPHRASE_LENGTH + ". Please generate one as soon as possible from the proxy console with \"/sn generate\".");
    }

    /**
     * Returns one immutable snapshot containing the current passphrase and property name.
     *
     * @return the current credentials snapshot
     */
    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * Returns the passphrase.
     *
     * @return the passphrase
     */
    public String getPassphrase() {
        return credentials.getPassphrase();
    }

    /**
     * Returns the property name.
     *
     * @return the property name
     */
    public String getPropertyName() {
        return credentials.getPropertyName();
    }

    /**
     * Immutable pair of values used during authentication.
     */
    public static final class Credentials {

        private final String passphrase;
        private final String propertyName;

        public Credentials(@NotNull String passphrase, @NotNull String propertyName) {
            this.passphrase = passphrase;
            this.propertyName = propertyName;
        }

        public String getPassphrase() {
            return passphrase;
        }

        public String getPropertyName() {
            return propertyName;
        }
    }
}