#ifndef SQUID_ANYP_TRAFFIC_MODE_H
#define SQUID_ANYP_TRAFFIC_MODE_H

namespace AnyP
{

/**
 * Set of 'mode' flags defining types of trafic which can be received.
 *
 * Use to determine the processing steps which need to be applied
 * to this traffic under any special circumstances which may apply.
 */
class TrafficMode
{
public:
    TrafficMode() : accelSurrogate(false), natIntercept(false), tproxyIntercept(false), tunnelSslBumping(false) {}
    TrafficMode(const TrafficMode &rhs) { operator =(rhs); }
    TrafficMode &operator =(const TrafficMode &rhs) { memcpy(this, &rhs, sizeof(TrafficMode)); return *this; }

    /** marks HTTP accelerator (reverse/surrogate proxy) traffic
     *
     * Indicating the following are required:
     *  - URL translation from relative to absolute form
     *  - restriction to origin peer relay recommended
     */
    bool accelSurrogate;

    /** marks NAT intercepted traffic
     *
     * Indicating the following are required:
     *  - NAT lookups
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - authentication prohibited
     */
    bool natIntercept;

    /** marks TPROXY intercepted traffic
     *
     * Indicating the following are required:
     *  - src/dst IP inversion must be performed
     *  - client IP should be spoofed if possible
     *  - URL translation from relative to absolute form
     *  - Same-Origin verification is mandatory
     *  - destination pinning is recommended
     *  - authentication prohibited
     */
    bool tproxyIntercept;

    /** marks intercept and decryption of CONNECT (tunnel) SSL traffic
     *
     * Indicating the following are required:
     *  - decryption of CONNECT request
     *  - URL translation from relative to absolute form
     *  - authentication prohibited on unwrapped requests (only on the CONNECT tunnel)
     *  - encrypted outbound server connections
     *  - peer relay prohibited. TODO: re-encrypt and re-wrap with CONNECT
     */
    bool tunnelSslBumping;

    /** true if the traffic is in any way intercepted
     *
     */
    bool isIntercepted() { return natIntercept||tproxyIntercept ;}
};

} // namespace AnyP

#endif
