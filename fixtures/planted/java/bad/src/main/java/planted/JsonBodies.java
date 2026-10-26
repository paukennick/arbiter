package planted;

public class JsonBodies {
    record Credentials(String username, String password) {}

    interface Context {
        <T> T bodyAsClass(Class<T> type);
    }

    static Credentials credentials(Context ctx) {
        return ctx.bodyAsClass(Credentials.class); // expect: arbiter/java.body-as-class-unguarded
    }
}
