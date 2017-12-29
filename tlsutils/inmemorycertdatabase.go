/* Copyright 2017 Robert Christian Taylor. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package tlsutils

import (
	"crypto/tls"
	"crypto/x509"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

//*****************************************************************************
//
//		              Certificate Database functionality
//
//*****************************************************************************

type certDatabaseEntry struct {
	//TLS cert associated with this entry
	tlsCert *tls.Certificate

	//The time the cert will expire. Cache this so we do not have to parse the
	//cert every time we need to look at this.
	expireTime time.Time

	//Time this database entry was last accessed. This value should be read
	//atomically and to setting it should be done with a compare and switch
	//atomic operation. This value will can change be changed by another process
	//when the read lock is held. However, when a write lock is held, this
	//value should only be changeable by the process holding the write lock.
	//
	//Note, this value should never be changed without first acquiring a read or
	//write lock.
	lastUsed int64

	//The host linked to the cert
	host string
}

//InMemoryCertDatabase is an implementation of an in memory database of TLS Certificates.
//The implementation supports auto certificate removal to prevent memory
//exhaustion. The implementation also provides a hook to allow consuming code
//to serialize the certificates to a backing store and a hook to change how
//certificates are generated.
type InMemoryCertDatabase struct {

	//Function to generate certificates for the database.
	GenerateCertificate func(host string) (certPem []byte, keyPem []byte, err error)

	//On Change notifier function. Notified code should not call back into
	//the Cert Database. This function should also be thread safe as it could
	//be called from multiple threads at the same time.
	CertificateDatabaseChange func(host string, certPem []byte, keyPem []byte)

	//More of a guideline then a rule, but the number of certs before the
	//database should start dropping old ones. If not set, default number is
	//used. If less then 0, no certs are ever dropped.
	MaxNumberOfCerts int

	//Number of certs to drop when the MaxNumberOfCerts threshold has been
	//exceeded. If not set, the default value is used.
	NumberOfCertsToDrop int

	//Host to cert mapping.
	certDatabase map[string]certDatabaseEntry

	//Read Write Mutex for database access.
	mutex sync.RWMutex

	//The number of certs stored in the database
	numberOfCertsInDatabase int
}

//Creates a new cert database.
func NewInMemoryCertDatabase(GenerateCertificate func(host string) (certPem []byte, keyPem []byte, err error)) (database *InMemoryCertDatabase) {
	database = new(InMemoryCertDatabase)

	database.MaxNumberOfCerts = 1024
	database.NumberOfCertsToDrop = 64
	database.certDatabase = make(map[string]certDatabaseEntry)
	database.numberOfCertsInDatabase = 0
	database.GenerateCertificate = GenerateCertificate

	return
}

//Gets a cert from the database, creating it if it does not exist.
func (database *InMemoryCertDatabase) GetCert(host string) (cert *tls.Certificate, err error) {

	cert, err = database.getCert(host)

	if err != nil {
		return
	}

	if cert != nil {
		return
	}

	cert, err = database.generateCert(host)

	return

}

func (database *InMemoryCertDatabase) getCert(host string) (cert *tls.Certificate, err error) {
	database.mutex.RLock()
	defer database.mutex.RUnlock()

	val, ok := database.certDatabase[host]

	if !ok {
		return
	}

	if time.Now().After(val.expireTime) {
		return
	}

	stamp := time.Now().Unix()

	lastUsed := atomic.LoadInt64(&val.lastUsed)

	//Do an atomic compare and set. Either it works or it does not. At most this
	//should cause the lastUsed time to be off by 1 or 2 seconds which is
	//not a big deal. Note, if the current time is greater then ours then
	//don't update the time stamp.
	if lastUsed < stamp {
		atomic.CompareAndSwapInt64(&val.lastUsed, lastUsed, stamp)
	}

	cert = val.tlsCert

	return

}

func (database *InMemoryCertDatabase) generateCert(host string) (cert *tls.Certificate, err error) {

	var certPem, keyPem []byte

	certPem, keyPem, err = database.GenerateCertificate(host)
	if err != nil {
		return
	}

	cert, err = database.addCert(host, certPem, keyPem)

	if err != nil {
		return
	}

	if database.CertificateDatabaseChange != nil {
		database.CertificateDatabaseChange(host, certPem, keyPem)
	}

	return
}

//Adds a new cert to the database. Does not trigger the database change event.
func (database *InMemoryCertDatabase) AddCert(host string, certPem []byte, keyPem []byte) (err error) {

	_, err = database.addCert(host, certPem, keyPem)

	return
}

func (database *InMemoryCertDatabase) addCert(host string, certPem []byte, keyPem []byte) (cert *tls.Certificate, err error) {

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)

	certParsed, err := x509.ParseCertificate(tlsCert.Certificate[0])

	if err != nil {
		return
	}

	entry := certDatabaseEntry{
		host:       host,
		tlsCert:    &tlsCert,
		expireTime: certParsed.NotAfter,
		lastUsed:   time.Now().Unix(),
	}

	// --- Entering Critical Section ---

	database.mutex.Lock()
	defer database.mutex.Unlock()

	//Run the trim command first since it would be awkward if the entry we just
	//added was removed.
	if database.MaxNumberOfCerts != 0 && database.numberOfCertsInDatabase >= database.MaxNumberOfCerts {
		database.trimDatabase()
	}

	_, ok := database.certDatabase[host]

	database.certDatabase[host] = entry

	if !ok {
		database.numberOfCertsInDatabase++
	}

	// --- Ending Critical Section ---

	cert = &tlsCert

	return
}

func (database *InMemoryCertDatabase) trimDatabase() {
	mapSize := len(database.certDatabase)
	entryList := make([]certDatabaseEntry, mapSize)

	for _, v := range database.certDatabase {
		entryList = append(entryList, v)
	}

	sort.Slice(entryList, func(i, j int) bool { return entryList[i].lastUsed < entryList[j].lastUsed })

	for i := 0; i < len(entryList) && i < database.NumberOfCertsToDrop; i++ {
		entry := entryList[i]
		delete(database.certDatabase, entry.host)
		database.numberOfCertsInDatabase--;
	}

}

//Clears all certs from the database. Does not trigger any database change
//events.
func (database *InMemoryCertDatabase) ClearDatabase() {
	database.mutex.Lock()
	defer database.mutex.Unlock()

	database.certDatabase = make(map[string]certDatabaseEntry)
	database.numberOfCertsInDatabase = 0
}
