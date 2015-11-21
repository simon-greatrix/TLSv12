/*
 * Copyright (c) 1999, 2009, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * 
 * This code is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 only, as published by
 * the Free Software Foundation. Oracle designates this particular file as
 * subject to the "Classpath" exception as provided by Oracle in the LICENSE
 * file that accompanied this code.
 * 
 * This code is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License version 2 for more
 * details (a copy is included in the LICENSE file that accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License version 2
 * along with this work; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA or
 * visit www.oracle.com if you need additional information or have any
 * questions.
 */

package tlsv12;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.*;

final class SSLSessionContextImpl implements SSLSessionContext {
    private MemoryCache sessionCache; // session cache, session id as key

    private MemoryCache sessionHostPortCache; // session cache, "host:port" as
                                              // key

    private int cacheLimit; // the max cache size

    private int timeout; // timeout in seconds


    // package private
    SSLSessionContextImpl() {
        cacheLimit = getDefaultCacheLimit(); // default cache size
        timeout = 86400; // default, 24 hours

        // use soft reference
        sessionCache = new MemoryCache(true, cacheLimit, timeout);
        sessionHostPortCache = new MemoryCache(true, cacheLimit, timeout);
    }


    /**
     * Returns the <code>SSLSession</code> bound to the specified session id.
     */
    public SSLSession getSession(byte[] sessionId) {
        if( sessionId == null ) {
            throw new NullPointerException("session id cannot be null");
        }

        SSLSessionImpl sess = (SSLSessionImpl) sessionCache.get(new SessionId(
                sessionId));
        if( !isTimedout(sess) ) {
            return sess;
        }

        return null;
    }


    /**
     * Returns an enumeration of the active SSL sessions.
     */
    public Enumeration<byte[]> getIds() {
        SessionCacheVisitor scVisitor = new SessionCacheVisitor();
        sessionCache.accept(scVisitor);

        return scVisitor.getSessionIds();
    }


    /**
     * Sets the timeout limit for cached <code>SSLSession</code> objects
     *
     * Note that after reset the timeout, the cached session before should be
     * timed within the shorter one of the old timeout and the new timeout.
     */
    public void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if( seconds < 0 ) {
            throw new IllegalArgumentException();
        }

        if( timeout != seconds ) {
            sessionCache.setTimeout(seconds);
            sessionHostPortCache.setTimeout(seconds);
            timeout = seconds;
        }
    }


    /**
     * Gets the timeout limit for cached <code>SSLSession</code> objects
     */
    public int getSessionTimeout() {
        return timeout;
    }


    /**
     * Sets the size of the cache used for storing <code>SSLSession</code>
     * objects.
     */
    public void setSessionCacheSize(int size) throws IllegalArgumentException {
        if( size < 0 ) throw new IllegalArgumentException();

        if( cacheLimit != size ) {
            sessionCache.setCapacity(size);
            sessionHostPortCache.setCapacity(size);
            cacheLimit = size;
        }
    }


    /**
     * Gets the size of the cache used for storing <code>SSLSession</code>
     * objects.
     */
    public int getSessionCacheSize() {
        return cacheLimit;
    }


    // package-private method, used ONLY by ServerHandshaker
    SSLSessionImpl get(byte[] id) {
        return (SSLSessionImpl) getSession(id);
    }


    // package-private method, used ONLY by ClientHandshaker
    SSLSessionImpl get(String hostname, int port) {
        /*
         * If no session caching info is available, we won't get one, so exit
         * before doing a lookup.
         */
        if( hostname == null && port == -1 ) {
            return null;
        }

        SSLSessionImpl sess = (SSLSessionImpl) sessionHostPortCache.get(getKey(
                hostname, port));
        if( !isTimedout(sess) ) {
            return sess;
        }

        return null;
    }


    private static String getKey(String hostname, int port) {
        return (hostname + ":" + String.valueOf(port)).toLowerCase();
    }


    // cache a SSLSession
    //
    // In SunJSSE implementation, a session is created while getting a
    // client hello or a server hello message, and cached while the
    // handshaking finished.
    // Here we time the session from the time it cached instead of the
    // time it created, which is a little longer than the expected. So
    // please do check isTimedout() while getting entry from the cache.
    void put(SSLSessionImpl s) {
        sessionCache.put(s.getSessionId(), s);

        // If no hostname/port info is available, don't add this one.
        if( (s.getPeerHost() != null) && (s.getPeerPort() != -1) ) {
            sessionHostPortCache.put(getKey(s.getPeerHost(), s.getPeerPort()),
                    s);
        }

        s.setContext(this);
    }


    // package-private method, remove a cached SSLSession
    void remove(SessionId key) {
        SSLSessionImpl s = (SSLSessionImpl) sessionCache.get(key);
        if( s != null ) {
            sessionCache.remove(key);
            sessionHostPortCache.remove(getKey(s.getPeerHost(), s.getPeerPort()));
        }
    }


    private static int getDefaultCacheLimit() {
        int cacheLimit = 0;
        try {
            String s = java.security.AccessController.doPrivileged(new java.security.PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty("javax.net.ssl.sessionCacheSize");
                }
            });
            cacheLimit = (s != null) ? Integer.valueOf(s).intValue() : 0;
        } catch (Exception e) {}

        return (cacheLimit > 0) ? cacheLimit : 0;
    }


    boolean isTimedout(SSLSession sess) {
        if( timeout == 0 ) {
            return false;
        }

        if( (sess != null)
                && ((sess.getCreationTime() + timeout * 1000L) <= (System.currentTimeMillis())) ) {
            sess.invalidate();
            return true;
        }

        return false;
    }

    final class SessionCacheVisitor implements MemoryCache.CacheVisitor {
        Vector<byte[]> ids = null;


        // public void visit(java.util.Map<Object, Object> map) {}
        public void visit(java.util.Map<Object, Object> map) {
            ids = new Vector<byte[]>(map.size());

            for(Object key:map.keySet()) {
                SSLSessionImpl value = (SSLSessionImpl) map.get(key);
                if( !isTimedout(value) ) {
                    ids.addElement(((SessionId) key).getId());
                }
            }
        }


        public Enumeration<byte[]> getSessionIds() {
            return ids != null ? ids.elements()
                    : new Vector<byte[]>().elements();
        }
    }

}




class MemoryCache {

    private final static float LOAD_FACTOR = 0.75f;

    // XXXX
    private final static boolean DEBUG = false;

    private final Map<Object, CacheEntry> cacheMap;

    private int maxSize;

    private long lifetime;

    private final ReferenceQueue<Object> queue;


    public MemoryCache(boolean soft, int maxSize, int lifetime) {
        this.maxSize = maxSize;
        this.lifetime = lifetime * 1000;
        this.queue = soft ? new ReferenceQueue<Object>() : null;
        int buckets = (int) (maxSize / LOAD_FACTOR) + 1;
        cacheMap = new LinkedHashMap<Object, CacheEntry>(buckets, LOAD_FACTOR,
                true);
    }


    /**
     * Empty the reference queue and remove all corresponding entries from the
     * cache.
     *
     * This method should be called at the beginning of each public method.
     */
    private void emptyQueue() {
        if( queue == null ) {
            return;
        }
        int startSize = cacheMap.size();
        while( true ) {
            CacheEntry entry = (CacheEntry) queue.poll();
            if( entry == null ) {
                break;
            }
            Object key = entry.getKey();
            if( key == null ) {
                // key is null, entry has already been removed
                continue;
            }
            CacheEntry currentEntry = cacheMap.remove(key);
            // check if the entry in the map corresponds to the expired
            // entry. If not, readd the entry
            if( (currentEntry != null) && (entry != currentEntry) ) {
                cacheMap.put(key, currentEntry);
            }
        }
        if( DEBUG ) {
            int endSize = cacheMap.size();
            if( startSize != endSize ) {
                System.out.println("*** Expunged " + (startSize - endSize)
                        + " entries, " + endSize + " entries left");
            }
        }
    }


    /**
     * Scan all entries and remove all expired ones.
     */
    private void expungeExpiredEntries() {
        emptyQueue();
        if( lifetime == 0 ) {
            return;
        }
        long time = System.currentTimeMillis();
        for(Iterator<CacheEntry> t = cacheMap.values().iterator();t.hasNext();) {
            CacheEntry entry = t.next();
            if( entry.isValid(time) == false ) {
                t.remove();
            }
        }
    }


    public synchronized void put(Object key, Object value) {
        emptyQueue();
        long expirationTime = (lifetime == 0) ? 0 : System.currentTimeMillis()
                + lifetime;
        CacheEntry newEntry = newEntry(key, value, expirationTime, queue);
        CacheEntry oldEntry = cacheMap.put(key, newEntry);
        if( oldEntry != null ) {
            oldEntry.invalidate();
            return;
        }
        if( maxSize > 0 && cacheMap.size() > maxSize ) {
            expungeExpiredEntries();
            if( cacheMap.size() > maxSize ) { // still too large?
                Iterator<CacheEntry> t = cacheMap.values().iterator();
                CacheEntry lruEntry = t.next();
                if( DEBUG ) {
                    System.out.println("** Overflow removal "
                            + lruEntry.getKey() + " | " + lruEntry.getValue());
                }
                t.remove();
                lruEntry.invalidate();
            }
        }
    }


    public synchronized Object get(Object key) {
        emptyQueue();
        CacheEntry entry = cacheMap.get(key);
        if( entry == null ) {
            return null;
        }
        long time = (lifetime == 0) ? 0 : System.currentTimeMillis();
        if( entry.isValid(time) == false ) {
            if( DEBUG ) {
                System.out.println("Ignoring expired entry");
            }
            cacheMap.remove(key);
            return null;
        }
        return entry.getValue();
    }


    public synchronized void remove(Object key) {
        emptyQueue();
        CacheEntry entry = cacheMap.remove(key);
        if( entry != null ) {
            entry.invalidate();
        }
    }


    public synchronized void setCapacity(int size) {
        expungeExpiredEntries();
        if( size > 0 && cacheMap.size() > size ) {
            Iterator<CacheEntry> t = cacheMap.values().iterator();
            for(int i = cacheMap.size() - size;i > 0;i--) {
                CacheEntry lruEntry = t.next();
                if( DEBUG ) {
                    System.out.println("** capacity reset removal "
                            + lruEntry.getKey() + " | " + lruEntry.getValue());
                }
                t.remove();
                lruEntry.invalidate();
            }
        }

        maxSize = size > 0 ? size : 0;

        if( DEBUG ) {
            System.out.println("** capacity reset to " + size);
        }
    }


    public synchronized void setTimeout(int timeout) {
        emptyQueue();
        lifetime = timeout > 0 ? timeout * 1000L : 0L;

        if( DEBUG ) {
            System.out.println("** lifetime reset to " + timeout);
        }
    }


    // it is a heavyweight method.
    public synchronized void accept(CacheVisitor visitor) {
        expungeExpiredEntries();
        Map<Object, Object> cached = getCachedEntries();

        visitor.visit(cached);
    }


    private Map<Object, Object> getCachedEntries() {
        Map<Object, Object> kvmap = new HashMap<Object, Object>(cacheMap.size());

        for(CacheEntry entry:cacheMap.values()) {
            kvmap.put(entry.getKey(), entry.getValue());
        }

        return kvmap;
    }


    protected <T> CacheEntry newEntry(Object key, T value, long expirationTime,
            ReferenceQueue<T> queue) {
        if( queue != null ) {
            return new SoftCacheEntry<T>(key, value, expirationTime, queue);
        }
        return new HardCacheEntry(key, value, expirationTime);
    }

    public interface CacheVisitor {
        public void visit(Map<Object, Object> map);
    }

    private static interface CacheEntry {
        boolean isValid(long currentTime);


        void invalidate();


        Object getKey();


        Object getValue();

    }

    private static class HardCacheEntry implements CacheEntry {
        private Object key, value;

        private long expirationTime;


        HardCacheEntry(Object key, Object value, long expirationTime) {
            this.key = key;
            this.value = value;
            this.expirationTime = expirationTime;
        }


        public Object getKey() {
            return key;
        }


        public Object getValue() {
            return value;
        }


        public boolean isValid(long currentTime) {
            boolean valid = (currentTime <= expirationTime);
            if( valid == false ) {
                invalidate();
            }
            return valid;
        }


        public void invalidate() {
            key = null;
            value = null;
            expirationTime = -1;
        }
    }

    private static class SoftCacheEntry<T> extends SoftReference<T> implements
            CacheEntry {

        private Object key;

        private long expirationTime;


        SoftCacheEntry(Object key, T value, long expirationTime,
                ReferenceQueue<T> queue) {
            super(value, queue);
            this.key = key;
            this.expirationTime = expirationTime;
        }


        public Object getKey() {
            return key;
        }


        public Object getValue() {
            return get();
        }


        public boolean isValid(long currentTime) {
            boolean valid = (currentTime <= expirationTime) && (get() != null);
            if( valid == false ) {
                invalidate();
            }
            return valid;
        }


        public void invalidate() {
            clear();
            key = null;
            expirationTime = -1;
        }
    }
}