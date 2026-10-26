package planted;

public class JsonBodies {
    record Credentials(String username, String password) {}

    interface Context {
        <T> T bodyAsClass(Class<T> type);
    }

    static Credentials credentials(Context ctx) {
        try {
            Credentials c = ctx.bodyAsClass(Credentials.class);
            if (c == null) throw new IllegalArgumentException("body required");
            return c;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed JSON", e);
        }
    }
}
