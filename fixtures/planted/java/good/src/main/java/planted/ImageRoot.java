package planted;

import java.nio.file.Path;

public class ImageRoot {
    private final Path baseDir;

    public ImageRoot(String dir) {
        this.baseDir = Path.of(dir == null ? "/srv/images" : dir).toAbsolutePath().normalize();
    }

    public Path resolve(String raw) {
        Path p = baseDir.resolve(raw).normalize();
        if (!p.startsWith(baseDir)) {
            throw new IllegalArgumentException("outside base directory");
        }
        return p;
    }
}
