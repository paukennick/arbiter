package planted;

import java.nio.file.Path;

public class ImageRoot {
    private final Path baseDir;

    public ImageRoot(String dir) {
        this.baseDir = dir == null ? null : Path.of(dir).toAbsolutePath().normalize();
    }

    public Path resolve(String raw) {
        Path p = Path.of(raw).toAbsolutePath().normalize();
        if (baseDir != null && !p.startsWith(baseDir)) { // expect: arbiter/java.path-confinement-optional
            throw new IllegalArgumentException("outside base directory");
        }
        return p;
    }
}
