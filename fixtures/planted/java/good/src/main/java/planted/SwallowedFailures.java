package planted;

import java.util.logging.Level;
import java.util.logging.Logger;

public class SwallowedFailures {
    private static final Logger LOG = Logger.getLogger(SwallowedFailures.class.getName());
    private final Runnable work;

    public SwallowedFailures(Runnable work) {
        this.work = work;
    }

    public void flush() {
        try {
            work.run();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "flush failed", e);
            throw new IllegalStateException(e);
        }
    }

    public int handle() {
        try {
            work.run();
            return 200;
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "request failed", e);
            return 500;
        }
    }
}
