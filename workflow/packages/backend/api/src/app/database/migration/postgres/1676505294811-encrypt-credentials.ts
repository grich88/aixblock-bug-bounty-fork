import { MigrationInterface, QueryRunner } from 'typeorm'
import { encryptUtils } from '../../../helper/encryption'
import { system } from '../../../helper/system/system'

const log = system.globalLogger()

export class encryptCredentials1676505294811 implements MigrationInterface {
    public async up(queryRunner: QueryRunner): Promise<void> {
        log.info('encryptCredentials1676505294811 up: started')
        const connections = await queryRunner.query('SELECT * FROM app_connection')
        for (const currentConnection of connections) {
            currentConnection.value = encryptUtils.encryptObject(currentConnection.value)
            // SECURITY FIX: Use parameterized queries to prevent SQL injection
            await queryRunner.query(
                'UPDATE app_connection SET value = $1 WHERE id = $2',
                [JSON.stringify(currentConnection.value), currentConnection.id]
            )
        }
        log.info('encryptCredentials1676505294811 up: finished')
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        log.info('encryptCredentials1676505294811 down: started')
        const connections = await queryRunner.query('SELECT * FROM app_connection')
        for (const currentConnection of connections) {
            try {
                currentConnection.value = encryptUtils.decryptObject(currentConnection.value)
                // SECURITY FIX: Use parameterized queries to prevent SQL injection
                await queryRunner.query(
                    'UPDATE app_connection SET value = $1 WHERE id = $2',
                    [JSON.stringify(currentConnection.value), currentConnection.id]
                )
            }
            catch (e) {
                log.error(e)
            }
        }
        log.info('encryptCredentials1676505294811 down: finished')
    }
}
