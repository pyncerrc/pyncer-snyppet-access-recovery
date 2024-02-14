<?php
namespace Pyncer\Snyppet\Access\Install\Recovery;

use Pyncer\Database\Table\Column\IntSize;
use Pyncer\Database\Table\ReferentialAction;
use Pyncer\Snyppet\AbstractInstall;

use const Pyncer\Snyppet\Access\RECOVERY_TOKEN_EXPIRATION as PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION;
use const Pyncer\Snyppet\Access\RECOVERY_CODE_LENGTH as PYNCER_ACCESS_RECOVERY_CODE_LENGTH;
use const Pyncer\Snyppet\Access\VALIDATE_CONTACT_MISMATCH as PYNCER_ACCESS_VALIDATE_CONTACT_MISMATCH;

class Install extends AbstractInstall
{
    /**
     * @inheritdoc
     */
    protected function safeInstall(): bool
    {
        $this->connection->createTable('user__recovery')
            ->serial('id')
            ->int('user_id', IntSize::BIG)->index()
            ->string('token', 96)->index()
            ->string('code', 25)->index()
            ->dateTime('expiration_date_time')->index()
            ->foreignKey(null, 'user_id')
                ->references('user', 'id')
                ->deleteAction(ReferentialAction::CASCADE)
                ->updateAction(ReferentialAction::CASCADE)
            ->execute();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function safeUninstall(): bool
    {
        if ($this->connection->hasTable('user__recovery')) {
            $this->connection->dropTable('user__recovery');
        }

        return true;
    }

    /**
     * @inheritdoc
     */
    public function getRequired(): array
    {
        return [
            'access' => '*'
        ];
    }

    /**
     * @inheritdoc
     */
    public function hasRelated(string $snyppetAlias): bool
    {
        switch ($snyppetAlias) {
            case 'config':
                return true;
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function installRelated(string $snyppetAlias): bool
    {
        switch ($snyppetAlias) {
            case 'config':
                return $this->installConfig();
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function uninstallRelated(string $snyppetAlias): bool
    {
        switch ($snyppetAlias) {
            case 'config':
                return $this->installConfig();
        }

        return false;
    }

    protected function installConfig(): bool
    {
        $config = new ConfigManager($this->connection);

        if (!$config->has('recovery_token_expiration')) {
            $config->set('recovery_token_expiration', PYNCER_ACCESS_RECOVERY_TOKEN_EXPIRATION);
            $config->setPreload('recovery_token_expiration', true);
            $config->save('recovery_token_expiration');
        }

        if (!$config->has('recovery_code_length')) {
            $config->set('recovery_code_length', PYNCER_ACCESS_RECOVERY_CODE_LENGTH);
            $config->setPreload('recovery_code_length', true);
            $config->save('recovery_code_length');
        }

        if (!$config->has('recovery_validate_contact_mismatch')) {
            $config->set('recovery_validate_contact_mismatch', PYNCER_ACCESS_VALIDATE_CONTACT_MISMATCH);
            $config->setPreload('recovery_validate_contact_mismatch', true);
            $config->save('recovery_validate_contact_mismatch');
        }

        return true;
    }

    protected function uninstallConfig(): bool
    {
        $config = new ConfigManager($this->connection);

        if (!$config->has('recovery_token_expiration')) {
            $config->set('recovery_token_expiration', null);
            $config->save('recovery_token_expiration');
        }

        if (!$config->has('recovery_code_length')) {
            $config->set('recovery_code_length', null);
            $config->save('recovery_code_length');
        }

        if (!$config->has('recovery_validate_contact_mismatch')) {
            $config->set('recovery_validate_contact_mismatch', null);
            $config->save('recovery_validate_contact_mismatch');
        }

        return true;
    }
}
