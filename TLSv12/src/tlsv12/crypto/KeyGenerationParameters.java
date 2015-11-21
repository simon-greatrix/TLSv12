package tlsv12.crypto;

import java.security.SecureRandom;

/**
 * The base class for parameters to key generators.
 */
public class KeyGenerationParameters
{
    private SecureRandom    random;
    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random the random byte source.
     * @param strength the size, in bits, of the keys we want to produce.
     */
    public KeyGenerationParameters(
        SecureRandom    random,
        int             strength)
    {
        this.random = random;
    }

    /**
     * return the random source associated with this
     * generator.
     *
     * @return the generators random source.
     */
    public SecureRandom getRandom()
    {
        return random;
    }
}
