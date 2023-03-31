package gr.xe.password.storage.util;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class BCryptPasswordHashProviderFactory implements PasswordHashProviderFactory {
    public static final String ID = "bcrypt";
    public static final int DEFAULT_ITERATIONS = 4; // default iterations of bcrypt algorithm @ oracle dbms

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new BCryptPasswordHashProvider(ID, DEFAULT_ITERATIONS);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }
}