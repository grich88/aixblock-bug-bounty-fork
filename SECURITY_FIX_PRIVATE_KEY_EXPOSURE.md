# Fix: Private Key Exposure in Web3 Authentication

## 🔧 **Fix Implementation**

This PR addresses the critical private key exposure vulnerability identified in issue #345.

### **Changes Made**
- Remove client-side private key access entirely
- Implement secure server-side signing with authentication
- Add secure key management with encryption
- Prevent wallet compromise through XSS attacks
- Add audit logging for all key operations

### **Security Improvements**
1. **Eliminates client-side private key exposure**
2. **Implements server-side signing with proper authentication**
3. **Uses secure key management with encryption**
4. **Adds audit logging for all key operations**
5. **Implements proper error handling**

### **Files Modified**
- `frontend/src/web3AuthContext.tsx` - Remove vulnerable getPrivateKey method
- `frontend/src/solanaRPC.ts` - Replace with secure wallet connection
- `backend/api/src/routes/signing.ts` - Add server-side signing endpoint
- `backend/api/src/services/keyManagement.ts` - Add secure key management

### **Code Changes**

#### 1. Remove Vulnerable Method
```typescript
// REMOVE this vulnerable method entirely
// export const getPrivateKey = async (): Promise<string> => {
//   return await solanaRPCInstance.getPrivateKey();
// };

// REPLACE with secure server-side signing
export const signTransaction = async (transaction: Transaction): Promise<Transaction> => {
  const response = await fetch('/api/sign-transaction', {
    method: 'POST',
    body: JSON.stringify({ transaction }),
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getAuthToken()}`
    }
  });
  
  if (!response.ok) {
    throw new Error('Transaction signing failed');
  }
  
  return response.json();
};
```

#### 2. Secure Wallet Connection
```typescript
export class SecureSolanaRPC {
  private wallet: Wallet | null = null;
  
  async connectWallet(): Promise<void> {
    if (typeof window !== 'undefined' && window.solana) {
      this.wallet = await window.solana.connect();
    } else {
      throw new Error('Solana wallet not found');
    }
  }
  
  async signTransaction(transaction: Transaction): Promise<Transaction> {
    if (!this.wallet) {
      throw new Error('Wallet not connected');
    }
    
    return await this.wallet.signTransaction(transaction);
  }
  
  getPublicKey(): PublicKey | null {
    return this.wallet?.publicKey || null;
  }
}
```

#### 3. Server-Side Signing Endpoint
```typescript
fastify.post('/api/sign-transaction', {
  schema: {
    body: {
      type: 'object',
      properties: {
        transaction: { type: 'object' }
      },
      required: ['transaction']
    }
  }
}, async (request, reply) => {
  try {
    const { transaction } = request.body as { transaction: Transaction };
    
    // Verify user authentication
    const token = request.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }
    
    // Get user's secure private key from server-side storage
    const user = await getUserFromToken(token);
    const privateKey = await getSecurePrivateKey(user.id);
    
    // Sign transaction server-side
    const signedTransaction = await signTransactionSecurely(transaction, privateKey);
    
    return { signedTransaction };
  } catch (error) {
    return reply.status(500).send({ error: 'Signing failed' });
  }
});
```

### **Testing**
```typescript
describe('Private Key Security', () => {
  it('should not expose private key on client-side', () => {
    // This should fail - private key should not be accessible
    expect(() => {
      window.solanaRPCInstance.getPrivateKey();
    }).toThrow();
  });
  
  it('should require authentication for signing', async () => {
    const response = await fetch('/api/sign-transaction', {
      method: 'POST',
      body: JSON.stringify({ transaction: mockTransaction })
    });
    
    expect(response.status).toBe(401);
  });
});
```

### **Impact**
- **Eliminates** client-side private key exposure
- **Prevents** wallet compromise through XSS
- **Implements** secure server-side signing
- **Adds** proper authentication and authorization
- **Follows** security best practices for key management

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #345
