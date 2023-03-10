package dns.cache;

import dns.core.*;
import java.util.*;

public class ZoneCache {
    public static Map<String, Map<String, Zone>> cache = new HashMap<>();
    public static Map<String, Zone> queryZone(String zone) {
        return cache.get(zone);
    }

}
