<?php
namespace Pyncer\Snyppet\Access\Component\Module\User\Recovery;

use Psr\Http\Message\ResponseInterface as PsrResponseInterface;
use Pyncer\App\Identifier as ID;
use Pyncer\Component\Module\AbstractModule;
use Pyncer\Http\Message\JsonResponse;
use Pyncer\Http\Message\Response;
use Pyncer\Http\Message\Status;
use Pyncer\Exception\UnexpectedValueException;
use Pyncer\Routing\Path\RoutingPathInterface;
use Pyncer\Snyppet\Access\Component\Forge\User\PasswordConfigTrait;
use Pyncer\Snyppet\Access\Table\User\UserMapper;
use Pyncer\Snyppet\Access\Table\User\RecoveryMapper;
use Pyncer\Snyppet\Access\Table\User\RecoveryModel;
use Pyncer\Snyppet\Access\User\PasswordConfig;

use function Pyncer\Array\ensure_keys as pyncer_array_ensure_keys;
use function Pyncer\String\nullify as pyncer_string_nullify;

use const PASSWORD_DEFAULT;
use const Pyncer\DATE_TIME_NOW as PYNCER_DATE_TIME_NOW;
use const Pyncer\Snyppet\Access\RECOVERY_MAX_ATTEMPTS as PYNCER_ACCESS_RECOVERY_MAX_ATTEMPTS;

class PatchRecoveryItemModule extends AbstractModule
{
    use PasswordConfigTrait;

    protected ?RoutingPathInterface $idRoutingPath = null;

    public function getIdRoutingPath(): ?RoutingPathInterface
    {
        return $this->idRoutingPath;
    }
    public function setIdRoutingPath(?RoutingPathInterface $value): static
    {
        $this->idRoutingPath = $value;
        return $this;
    }

    protected function getPrimaryResponse(): PsrResponseInterface
    {
        $idRoutingPath = $this->getIdRoutingPath()?->getRouteDirPath() ?? '@id64';
        if ($idRoutingPath === '@id64') {
            $token = $this->queryParams->getString(
                $this->getIdRoutingPath()?->getQueryName() ?? 'id64',
                null
            );
        } else {

            throw new UnexpectedValueException(
                'Id routing path is not supported. (' . $idRoutingPath . ')'
            );
        }

        if ($token === null) {
            return new Response(
                Status::CLIENT_ERROR_404_NOT_FOUND
            );
        }

        $connection = $this->get(ID::DATABASE);
        $recoveryMapper = new RecoveryMapper($connection);
        $recoveryModel = $recoveryMapper->selectByToken($token);

        if (!$recoveryModel) {
            return new Response(
                Status::CLIENT_ERROR_404_NOT_FOUND
            );
        }

        $userMapper = new UserMapper($connection);
        $userModel = $userMapper->selectById($recoveryModel->getUserId());

        if (!$userModel) {
            $recoveryMapper->delete($recoveryModel);

            return new Response(
                Status::CLIENT_ERROR_404_NOT_FOUND
            );
        }

        if ($recoveryModel->getExpirationDateTime() < PYNCER_DATE_TIME_NOW) {
            return new JsonResponse(
                Status::CLIENT_ERROR_401_UNAUTHORIZED,
                [
                    'errors' => ['general' => 'expired']
                ]
            );
        }

        if ($recoveryModel->getAttempts() >= PYNCER_ACCESS_RECOVERY_MAX_ATTEMPTS) {
            return new JsonResponse(
                Status::CLIENT_ERROR_422_UNPROCESSABLE_ENTITY,
                [
                    'errors' => ['code' => 'attempts']
                ]
            );
        }

        $data = $this->getRequestItemData();

        [$data, $errors] = $this->validateItemData($data);

        if (!array_key_exists('code', $errors) &&
            $recoveryModel->getCode() !== $data['code']
        ) {
            $errors['code'] = 'mismatch';
        }

        if ($errors) {
            $this->increaseRecoveryAttempts($recoveryModel->getId());

            return new JsonResponse(
                Status::CLIENT_ERROR_422_UNPROCESSABLE_ENTITY,
                ['errors' => $errors]
            );
        }

        $userModel->setPassword($data['password']);
        $userMapper->update($userModel);

        return new Response(
            Status::SUCCESS_204_NO_CONTENT
        );
    }

    protected function increaseRecoveryAttempts(int $id): void
    {
        $connection = $this->get(ID::DATABASE);

        $attempts = $connection->functions('user__recovery', 'Add')
            ->arguments('attempts', 1);

        $connection->update('user__recovery')
            ->values([
                'attempts' => $attempts
            ])
            ->where([
                'id' => $id
            ])
            ->execute();
    }

    protected function getRequestItemData(): array
    {
        $keys = $this->getRequestItemKeys();
        $data = $this->parsedBody->getData();
        return pyncer_array_ensure_keys($data, $keys);
    }

    protected function getRequestItemKeys(): ?array
    {
        if ($this->getPasswordConfig()->getConfirmNew()) {
            $keys = ['password1', 'password2'];
        } else {
            $keys = ['password'];
        }

        $keys[] = 'code';

        return $keys;
    }

    protected function validateItemData(array $data): array
    {
        $errors = [];

        $data['code'] = pyncer_string_nullify($data['code']);

        if ($data['code'] === null) {
            $errors['code'] = 'required';
        }

        if ($this->getPasswordConfig()->getConfirmNew()) {
            $password = pyncer_string_nullify($data['password1'] ?? null);
            $password2 = pyncer_string_nullify($data['password2'] ?? null);

            if ($password === null) {
                $errors['password1'] = 'required';
            }

            if ($password2 === null) {
                $errors['password2'] = 'required';
            }

            if ($password !==  null &&
                $password2 !== null &&
                $password !== $password2
            ) {
                $errors['password1'] = 'mismatch';
            }
        } else {
            $password = pyncer_string_nullify($data['password']);

            if ($password === null) {
                $errors['password'] = 'required';
            }
        }

        if ($password !== null && !$errors) {
            $passwordRule = $this->getPasswordConfig()->getValidationRule();

            if (!$passwordRule->isValid($password)) {
                $errors['password'] = $passwordRule->getError();
            } else {
                $password = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );
            }
        }

        if ($errors) {
            $data['password'] = null;
        } else {
            $data['password'] = $password;
        }

        if ($this->getPasswordConfig()->getConfirmNew() &&
            array_key_exists('password', $errors)
        ) {
            $errors['password1'] = $errors['password'];
            unset($errors['password']);
        }

        return [$data, $errors];
    }

}
