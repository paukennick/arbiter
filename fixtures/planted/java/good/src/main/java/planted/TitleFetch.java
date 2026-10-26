package planted;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TitleFetch {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(3)).build();

    private static InetAddress publicAddress(String host) throws Exception {
        InetAddress a = InetAddress.getByName(host);
        if (a.isLoopbackAddress() || a.isSiteLocalAddress()) return null;
        return a;
    }

    public String fetch(String url) throws Exception {
        URI uri = URI.create(url);
        InetAddress ip = publicAddress(uri.getHost());
        if (ip == null) return null;
        InetSocketAddress pinned = new InetSocketAddress(ip, 443);
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://" + pinned.getHostString() + "/")).timeout(java.time.Duration.ofSeconds(5)).GET().build();
        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }
}
