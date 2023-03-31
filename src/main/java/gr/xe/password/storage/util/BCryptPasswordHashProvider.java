package gr.xe.password.storage.util;


import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import static org.springframework.security.crypto.bcrypt.BCrypt.*;


public class BCryptPasswordHashProvider implements PasswordHashProvider {
    private final int defaultIterations;
    private final String providerId;

    public BCryptPasswordHashProvider(final String providerId, final int defaultIterations) {
        this.providerId = providerId;
        this.defaultIterations = defaultIterations;
    }

    @Override
    public boolean policyCheck(PasswordPolicy passwordPolicy, PasswordCredentialModel passwordCredentialModel) {
        final int policyHashIterations = passwordPolicy.getHashIterations() == -1 ? defaultIterations : passwordPolicy.getHashIterations();

        return passwordCredentialModel.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(passwordCredentialModel.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        final String encodedPassword = encode(rawPassword, iterations);

        // bcrypt salt is stored as part of the encoded password so no need to store salt separately
        return PasswordCredentialModel.createFromValues(providerId, new byte[0], iterations, encodedPassword);
    }

    @Override
    public String encode(String rawPassword, int iterations) {
        final int cost = iterations == -1 ? defaultIterations : iterations;
        String salt = gensalt(cost);
        return hashpw(rawPassword, salt);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        final String hash = credential.getPasswordSecretData().getValue();
        return checkpw(rawPassword, hash);
    }

    @Override
    public void close() {

    }
}