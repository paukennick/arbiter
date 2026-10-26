package planted;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TitleFetch {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(3)).build();

    private static boolean isPublicHost(String host) throws Exception {
        for (InetAddress a : InetAddress.getAllByName(host)) {
            if (a.isLoopbackAddress() || a.isSiteLocalAddress()) return false;
        }
        return true;
    }

    public String fetch(String url) throws Exception {
        URI uri = URI.create(url);
        if (!isPublicHost(uri.getHost())) return null; // expect: arbiter/java.ssrf-check-then-connect
        HttpRequest req = HttpRequest.newBuilder(uri).timeout(java.time.Duration.ofSeconds(5)).GET().build();
        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }
}
