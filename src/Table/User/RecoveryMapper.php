<?php
namespace Pyncer\Snyppet\Access\Table\User;

use Pyncer\Snyppet\Access\Table\User\RecoveryModel;
use Pyncer\Data\Mapper\AbstractMapper;
use Pyncer\Data\Model\ModelInterface;

class RecoveryMapper extends AbstractMapper
{
    public function getTable(): string
    {
        return 'user__recovery';
    }

    public function forgeModel(iterable $data = []): ModelInterface
    {
        return new RecoveryModel($data);
    }

    public function isValidModel(ModelInterface $model): bool
    {
        return ($model instanceof RecoveryModel);
    }

    public function selectByToken(
        string $token,
    ): ?ModelInterface
    {
        return $this->selectByColumns(
            ['token' => $token],
        );
    }
}
